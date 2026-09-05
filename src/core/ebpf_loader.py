"""
eBPF Loader module: Abstract base loader, Mock loader for cross-platform testing, and BCC production loader.
"""
from abc import ABC, abstractmethod
import os
import random
import socket
import struct
import sys
import threading
import time
from typing import List, Optional

from src.storage.models import FlowKey, FlowValue, RawFlowMetric


class AbstractBPFLoader(ABC):
    """Abstract interface for eBPF kernel interaction."""

    @abstractmethod
    def load(self) -> None:
        """Compile and attach eBPF probes."""
        pass

    @abstractmethod
    def poll_flow_stats(self) -> List[RawFlowMetric]:
        """Poll and atomically drain accumulated flow metrics from kernel maps."""
        pass

    @abstractmethod
    def cleanup(self) -> None:
        """Detach probes and release eBPF maps."""
        pass


class MockBPFLoader(AbstractBPFLoader):
    """
    Mock eBPF loader for non-Linux platforms (Windows/macOS) and unit testing.
    Generates synthetic, deterministic TCP/UDP network flows.
    """

    def __init__(self, synthetic_pids: Optional[List[int]] = None):
        self._is_loaded = False
        self._profiles = [
            {"pid": 1001, "comm": "chrome", "proto": 6, "rem_ip": "142.250.190.46", "port": 443, "tx_range": (1500, 18000), "rx_range": (25000, 480000)},
            {"pid": 1002, "comm": "spotify", "proto": 6, "rem_ip": "151.101.65.140", "port": 443, "tx_range": (500, 3000), "rx_range": (60000, 180000)},
            {"pid": 1003, "comm": "discord", "proto": 17, "rem_ip": "162.159.130.233", "port": 50001, "tx_range": (2000, 8000), "rx_range": (4000, 16000)},
            {"pid": 1004, "comm": "curl", "proto": 6, "rem_ip": "93.184.216.34", "port": 443, "tx_range": (800, 4000), "rx_range": (10000, 80000)},
            {"pid": 1005, "comm": "python", "proto": 6, "rem_ip": "151.101.0.223", "port": 443, "tx_range": (1000, 5000), "rx_range": (80000, 600000)},
            {"pid": 1006, "comm": "docker", "proto": 6, "rem_ip": "54.236.113.205", "port": 443, "tx_range": (4000, 40000), "rx_range": (120000, 1200000)},
            {"pid": 1007, "comm": "slack", "proto": 6, "rem_ip": "13.249.132.84", "port": 443, "tx_range": (600, 4500), "rx_range": (5000, 35000)},
            {"pid": 1008, "comm": "node", "proto": 6, "rem_ip": "104.16.27.35", "port": 443, "tx_range": (1200, 12000), "rx_range": (15000, 150000)},
            {"pid": 1009, "comm": "postgres", "proto": 6, "rem_ip": "10.0.0.15", "port": 5432, "tx_range": (5000, 50000), "rx_range": (10000, 90000)},
            {"pid": 1010, "comm": "zoom", "proto": 17, "rem_ip": "170.114.10.12", "port": 8801, "tx_range": (15000, 60000), "rx_range": (20000, 85000)},
            {"pid": 1011, "comm": "steam", "proto": 6, "rem_ip": "23.210.180.50", "port": 443, "tx_range": (2000, 10000), "rx_range": (350000, 2500000)},
            {"pid": 2045, "comm": "dnsmasq", "proto": 17, "rem_ip": "8.8.8.8", "port": 53, "tx_range": (64, 256), "rx_range": (0, 0)},
        ]
        if synthetic_pids:
            self._profiles = [p for p in self._profiles if p["pid"] in synthetic_pids]
        self._local_ip = "192.168.1.50"

    def load(self) -> None:
        self._is_loaded = True

    def _ip_to_int(self, ip_str: str) -> int:
        return struct.unpack("<I", socket.inet_aton(ip_str))[0]

    def poll_flow_stats(self) -> List[RawFlowMetric]:
        if not self._is_loaded:
            raise RuntimeError("BPF loader is not loaded. Call load() first.")

        now_ns = int(time.time() * 1e9)
        metrics = []

        for p in self._profiles:
            pid = p["pid"]
            comm = p["comm"]
            proto = p["proto"]
            rem_ip = p["rem_ip"]
            port = p["port"]
            local_port = 50000 + (pid % 1000)

            # Upload (EGRESS)
            tx_min, tx_max = p["tx_range"]
            if tx_max > 0:
                tx_bytes = random.randint(tx_min, tx_max)
                metrics.append(
                    RawFlowMetric(
                        key=FlowKey(
                            pid=pid,
                            saddr=self._ip_to_int(self._local_ip),
                            daddr=self._ip_to_int(rem_ip),
                            sport=local_port,
                            dport=port,
                            proto=proto,
                            direction=0,  # EGRESS
                        ),
                        val=FlowValue(
                            bytes=tx_bytes,
                            packets=max(1, tx_bytes // 1400),
                            first_seen_ns=now_ns - 1000000,
                            last_seen_ns=now_ns,
                            comm=comm,
                        ),
                    )
                )

            # Download (INGRESS)
            rx_min, rx_max = p["rx_range"]
            if rx_max > 0:
                rx_bytes = random.randint(rx_min, rx_max)
                metrics.append(
                    RawFlowMetric(
                        key=FlowKey(
                            pid=pid,
                            saddr=self._ip_to_int(rem_ip),
                            daddr=self._ip_to_int(self._local_ip),
                            sport=port,
                            dport=local_port,
                            proto=proto,
                            direction=1,  # INGRESS
                        ),
                        val=FlowValue(
                            bytes=rx_bytes,
                            packets=max(1, rx_bytes // 1400),
                            first_seen_ns=now_ns - 1000000,
                            last_seen_ns=now_ns,
                            comm=comm,
                        ),
                    )
                )

        return metrics

    def cleanup(self) -> None:
        self._is_loaded = False


class BCCBPFLoader(AbstractBPFLoader):
    """
    Production Linux eBPF Loader using BCC with real-time perf buffer queue.
    """

    def __init__(self, bpf_source_path: Optional[str] = None):
        if bpf_source_path is None:
            self.bpf_source_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "bpf", "tracker.bpf.c")
            )
        else:
            self.bpf_source_path = os.path.abspath(bpf_source_path)
        self.bpf = None
        self._queue: List[RawFlowMetric] = []
        self._lock = threading.Lock()

    def _event_cb(self, cpu, data, size):
        event = self.bpf["flow_events"].event(data)
        key = FlowKey(
            pid=event.pid,
            saddr=event.saddr,
            daddr=event.daddr,
            sport=event.sport,
            dport=event.dport,
            proto=event.proto,
            direction=event.direction,
        )
        val = FlowValue(
            bytes=event.bytes,
            packets=1,
            comm=event.comm.decode("utf-8", "replace").rstrip("\x00"),
        )
        with self._lock:
            self._queue.append(RawFlowMetric(key=key, val=val))

    def load(self) -> None:
        for p in ["/usr/lib/python3/dist-packages", "/usr/local/lib/python3/dist-packages"]:
            if p not in sys.path:
                sys.path.append(p)

        try:
            from bcc import BPF  # type: ignore
        except ImportError:
            raise RuntimeError(
                "BCC is not installed or not supported on this platform.\n"
                "To install on Ubuntu / WSL2, run:\n"
                "  sudo apt update && sudo apt install -y bpfcc-tools python3-bpfcc libbpfcc-dev\n"
                "Or run in mock mode:\n"
                "  ./run.sh --mock"
            )

        if not os.path.exists(self.bpf_source_path):
            raise FileNotFoundError(f"eBPF source file not found at: {self.bpf_source_path}")

        with open(self.bpf_source_path, "r") as f:
            src = f.read()

        self.bpf = BPF(text=src)

        probes = [
            ("kprobe", "tcp_sendmsg", "trace_tcp_sendmsg"),
            ("kprobe", "tcp_cleanup_rbuf", "trace_tcp_cleanup_rbuf"),
            ("kprobe", "udp_sendmsg", "trace_udp_sendmsg"),
        ]

        attached_count = 0
        for probe_type, event, fn_name in probes:
            try:
                self.bpf.attach_kprobe(event=event, fn_name=fn_name)
                attached_count += 1
            except Exception as e:
                print(f"[BPF WARNING] Could not attach {probe_type} to '{event}': {e}")

        if attached_count == 0:
            raise RuntimeError("Failed to attach any eBPF kernel probes.")

        self.bpf["flow_events"].open_perf_buffer(self._event_cb, page_cnt=64)

    def poll_flow_stats(self, timeout_ms: int = 25) -> List[RawFlowMetric]:
        if not self.bpf:
            return []

        try:
            self.bpf.perf_buffer_poll(timeout=timeout_ms)
        except Exception:
            pass

        with self._lock:
            metrics = self._queue
            self._queue = []
            return metrics

    def cleanup(self) -> None:
        if self.bpf:
            try:
                self.bpf.cleanup()
            except Exception:
                pass
            self.bpf = None

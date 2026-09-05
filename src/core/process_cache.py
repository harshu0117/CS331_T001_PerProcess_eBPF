"""
Process Resolution and Caching Subsystem.
Inspects /proc on Linux or psutil cross-platform with TTL caching to resolve PIDs to rich metadata.
"""
from datetime import datetime, timedelta, timezone
import os
from typing import Dict, Optional
try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

from src.storage.models import ProcessInfo


class ProcessCache:
    """
    Caches process metadata (comm, cmdline, username, uid) with configurable TTL.
    """

    def __init__(self, ttl_seconds: int = 10):
        self.ttl = timedelta(seconds=ttl_seconds)
        self._cache: Dict[int, ProcessInfo] = {}

    def get(self, pid: int, fallback_comm: str = "") -> ProcessInfo:
        now = datetime.now(timezone.utc)
        if pid in self._cache:
            entry = self._cache[pid]
            if (now - entry.last_seen) < self.ttl:
                entry.last_seen = now
                return entry

        # Resolve process info
        info = self._resolve_pid(pid, fallback_comm)
        self._cache[pid] = info
        return info

    def _resolve_pid(self, pid: int, fallback_comm: str) -> ProcessInfo:
        now = datetime.now(timezone.utc)

        # Try /proc on Linux
        proc_comm_path = f"/proc/{pid}/comm"
        proc_cmdline_path = f"/proc/{pid}/cmdline"

        if os.path.exists(proc_comm_path):
            try:
                with open(proc_comm_path, "r") as f:
                    comm = f.read().strip()
                cmdline = ""
                if os.path.exists(proc_cmdline_path):
                    with open(proc_cmdline_path, "rb") as f:
                        cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
                return ProcessInfo(
                    pid=pid,
                    comm=comm or fallback_comm,
                    cmdline=cmdline,
                    uid=None,
                    username="linux_user",
                    first_seen=now,
                    last_seen=now,
                )
            except (IOError, PermissionError):
                pass

        # Fallback to psutil
        if HAVE_PSUTIL:
            try:
                p = psutil.Process(pid)
                return ProcessInfo(
                    pid=pid,
                    comm=p.name() or fallback_comm,
                    cmdline=" ".join(p.cmdline()) if p.cmdline() else "",
                    username=p.username() if hasattr(p, "username") else "unknown",
                    first_seen=now,
                    last_seen=now,
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Last resort fallback to kernel-cached comm
        return ProcessInfo(
            pid=pid,
            comm=fallback_comm or f"pid_{pid}",
            cmdline="",
            username="unknown",
            first_seen=now,
            last_seen=now,
        )

    def invalidate(self, pid: int) -> None:
        self._cache.pop(pid, None)

    def clear(self) -> None:
        self._cache.clear()

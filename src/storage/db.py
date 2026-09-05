"""
SQLite Storage Engine with WAL Mode, Batch Insertion, and Historical Analytics.
"""
from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Any, Dict, List, Optional

from src.storage.models import AggregatedFlowRecord, ProcessInfo


class DatabaseManager:
    """
    Manages SQLite database storage for real-time and historical network analytics.
    """

    def __init__(self, db_path: str = "network_usage.db"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS processes (
                    pid INTEGER PRIMARY KEY,
                    comm TEXT NOT NULL,
                    cmdline TEXT,
                    uid INTEGER,
                    username TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS traffic_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    pid INTEGER,
                    comm TEXT NOT NULL,
                    proto TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    bytes_delta INTEGER NOT NULL,
                    packets_delta INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    rate_bps REAL DEFAULT 0.0
                );

                CREATE TABLE IF NOT EXISTS traffic_hourly_aggregates (
                    bucket_start TIMESTAMP NOT NULL,
                    pid INTEGER NOT NULL,
                    comm TEXT NOT NULL,
                    proto TEXT NOT NULL,
                    remote_ip TEXT NOT NULL,
                    total_bytes_sent INTEGER DEFAULT 0,
                    total_bytes_recv INTEGER DEFAULT 0,
                    total_packets_sent INTEGER DEFAULT 0,
                    total_packets_recv INTEGER DEFAULT 0,
                    PRIMARY KEY (bucket_start, pid, proto, remote_ip)
                );

                CREATE INDEX IF NOT EXISTS idx_snapshots_time_pid ON traffic_snapshots(timestamp, pid);
                CREATE INDEX IF NOT EXISTS idx_snapshots_proto ON traffic_snapshots(proto);
                CREATE INDEX IF NOT EXISTS idx_snapshots_dst_ip ON traffic_snapshots(dst_ip);
                """
            )

    def upsert_process(self, info: ProcessInfo) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO processes (pid, comm, cmdline, uid, username, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(pid) DO UPDATE SET
                    comm=excluded.comm,
                    cmdline=excluded.cmdline,
                    username=excluded.username,
                    last_seen=excluded.last_seen
                """,
                (
                    info.pid,
                    info.comm,
                    info.cmdline,
                    info.uid,
                    info.username,
                    info.first_seen.isoformat(),
                    info.last_seen.isoformat(),
                ),
            )

    def insert_snapshot_batch(self, records: List[AggregatedFlowRecord]) -> None:
        if not records:
            return

        payload = [
            (
                r.timestamp.isoformat(),
                r.pid,
                r.comm,
                r.proto,
                r.direction,
                r.src_ip,
                r.src_port,
                r.dst_ip,
                r.dst_port,
                r.bytes_delta,
                r.packets_delta,
                r.duration_ms,
                r.rate_bps,
            )
            for r in records
        ]

        with self._get_connection() as conn:
            conn.executemany(
                """
                INSERT INTO traffic_snapshots (
                    timestamp, pid, comm, proto, direction, src_ip, src_port,
                    dst_ip, dst_port, bytes_delta, packets_delta, duration_ms, rate_bps
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                payload,
            )

    def get_top_processes(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 10,
        proto: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        start_str = (start_time or (datetime.now(timezone.utc) - timedelta(hours=1))).isoformat()
        end_str = (end_time or datetime.now(timezone.utc)).isoformat()

        query = """
            SELECT 
                pid, 
                comm,
                SUM(CASE WHEN direction = 'EGRESS' THEN bytes_delta ELSE 0 END) AS total_sent,
                SUM(CASE WHEN direction = 'INGRESS' THEN bytes_delta ELSE 0 END) AS total_recv,
                SUM(bytes_delta) AS total_bytes,
                COUNT(DISTINCT dst_ip) AS distinct_ips
            FROM traffic_snapshots
            WHERE timestamp BETWEEN ? AND ?
        """
        params: List[Any] = [start_str, end_str]

        if proto and proto != "ALL":
            query += " AND proto = ?"
            params.append(proto)

        query += """
            GROUP BY pid, comm
            ORDER BY total_bytes DESC
            LIMIT ?
        """
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def get_remote_ip_breakdown(
        self,
        pid: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        start_str = (start_time or (datetime.now(timezone.utc) - timedelta(hours=1))).isoformat()
        end_str = (end_time or datetime.now(timezone.utc)).isoformat()

        query = """
            SELECT 
                dst_ip AS remote_ip,
                proto,
                SUM(bytes_delta) AS total_bytes,
                SUM(packets_delta) AS total_packets
            FROM traffic_snapshots
            WHERE timestamp BETWEEN ? AND ?
        """
        params: List[Any] = [start_str, end_str]

        if pid is not None:
            query += " AND pid = ?"
            params.append(pid)

        query += """
            GROUP BY dst_ip, proto
            ORDER BY total_bytes DESC
            LIMIT ?
        """
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def get_protocol_distribution(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, int]:
        start_str = (start_time or (datetime.now(timezone.utc) - timedelta(hours=1))).isoformat()
        end_str = (end_time or datetime.now(timezone.utc)).isoformat()

        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT proto, SUM(bytes_delta) AS total_bytes
                FROM traffic_snapshots
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY proto
                """,
                (start_str, end_str),
            ).fetchall()
            return {row["proto"]: row["total_bytes"] for row in rows}

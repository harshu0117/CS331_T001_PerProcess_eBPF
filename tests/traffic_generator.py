"""
Synthetic TCP/UDP traffic generator harness for local socket testing.
Generates predictable packet bursts and measures ground truth byte counts.
"""
import socket
import threading
import time
from typing import Tuple


def start_tcp_echo_server(host: str = "127.0.0.1", port: int = 19999) -> Tuple[socket.socket, threading.Thread]:
    """Starts a lightweight TCP echo server in a background thread."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)

    def _serve():
        try:
            conn, _ = server_sock.accept()
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return server_sock, t


def send_tcp_payload(host: str = "127.0.0.1", port: int = 19999, total_bytes: int = 100000) -> int:
    """Sends payload via TCP and returns total bytes sent."""
    chunk = b"X" * 1024
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
        client_sock.connect((host, port))
        while sent < total_bytes:
            to_send = min(len(chunk), total_bytes - sent)
            client_sock.sendall(chunk[:to_send])
            sent += to_send
    return sent


def send_udp_datagrams(host: str = "127.0.0.1", port: int = 19998, packet_count: int = 100, packet_size: int = 512) -> int:
    """Sends UDP datagrams and returns total bytes sent."""
    data = b"U" * packet_size
    sent_bytes = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(packet_count):
            sock.sendto(data, (host, port))
            sent_bytes += len(data)
    return sent_bytes

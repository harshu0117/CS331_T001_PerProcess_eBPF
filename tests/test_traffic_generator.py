"""
Unit tests for the synthetic traffic generator harness.
"""
import time
from tests.traffic_generator import send_tcp_payload, send_udp_datagrams, start_tcp_echo_server


def test_tcp_traffic_generator():
    server_sock, thread = start_tcp_echo_server(port=19991)
    time.sleep(0.1)

    sent_bytes = send_tcp_payload(port=19991, total_bytes=50000)
    assert sent_bytes == 50000
    server_sock.close()


def test_udp_traffic_generator():
    sent_bytes = send_udp_datagrams(port=19992, packet_count=50, packet_size=256)
    assert sent_bytes == 50 * 256

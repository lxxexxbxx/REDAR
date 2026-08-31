"""대상 응답 확인 검증.

포트 범위는 대부분이 닫힌 포트다. 전부에 템플릿을 돌리면 시간만 쓴다.
다만 건너뛴 것을 감추면 점검 범위가 과장되므로 기록이 함께 남아야 한다 (절대규칙 10)
"""
from __future__ import annotations

import socket
import threading

import pytest

from app.adapters import portprobe


@pytest.fixture
def listening_port():
    """실제로 열린 포트 1개. 외부에 요청을 보내지 않고 자기 자신만 확인"""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    stop = threading.Event()

    def accept_loop() -> None:
        server.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                continue

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()
    yield port
    stop.set()
    thread.join(timeout=1)
    server.close()


def _closed_port() -> int:
    """바인드 후 즉시 닫아 확실히 비어 있는 포트를 얻음"""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_open_port_detected(listening_port):
    assert portprobe.is_open("127.0.0.1", listening_port) is True


def test_closed_port_detected():
    assert portprobe.is_open("127.0.0.1", _closed_port()) is False


def test_reachable_keeps_input_order(listening_port):
    closed = _closed_port()
    targets = [
        f"http://127.0.0.1:{closed}",
        f"http://127.0.0.1:{listening_port}",
    ]
    assert portprobe.reachable(targets) == [f"http://127.0.0.1:{listening_port}"]


def test_targets_without_port_pass_through():
    """포트를 확정할 수 없으면 nuclei 가 기본 포트로 처리. 여기서 버리면 안 됨"""
    assert portprobe.reachable(["example.invalid"]) == ["example.invalid"]


def test_empty_input():
    assert portprobe.reachable([]) == []


def test_unresolvable_host_is_not_reachable():
    result = portprobe.reachable(["http://nonexistent.invalid:8080"], timeout=0.2)
    assert result == []

"""처리 과정 로그 버퍼 검증.

파일로 남기지 않는다. 용량이 계속 늘고 사용자 데이터 경로를 관리해야 하므로
메모리 링 버퍼만 두고, 개수와 시간 두 겹으로 제한한다
"""
from __future__ import annotations

import logging

import pytest

from app.adapters import logbuffer


@pytest.fixture(autouse=True)
def clean():
    logbuffer.clear()
    yield
    logbuffer.clear()


def test_append_and_read():
    logbuffer.append("nuclei", "Templates loaded for current scan: 13412")
    items = logbuffer.entries()
    assert len(items) == 1
    assert items[0]["source"] == "nuclei"
    assert "13412" in items[0]["message"]


def test_cursor_returns_only_new_lines():
    """화면이 커서를 들고 폴링. 같은 줄을 다시 받으면 화면이 중복됨"""
    logbuffer.append("a", "첫째")
    first = logbuffer.entries()
    logbuffer.append("a", "둘째")

    fresh = logbuffer.entries(after=first[-1]["seq"])
    assert [i["message"] for i in fresh] == ["둘째"]


def test_ring_drops_oldest():
    """개수 상한. 무한정 쌓이면 메모리가 계속 늘어남"""
    for i in range(logbuffer._MAX + 50):
        logbuffer.append("bulk", f"line-{i}")
    items = logbuffer.entries(limit=logbuffer._MAX)
    assert len(items) <= logbuffer._MAX
    assert items[-1]["message"] == f"line-{logbuffer._MAX + 49}"


def test_expired_lines_hidden(monkeypatch):
    """'스캔 끝나고 한동안' 만 보관. 오래된 줄은 조회에서 빠짐"""
    logbuffer.append("old", "지난 줄")
    real = logbuffer.time.time
    monkeypatch.setattr(
        logbuffer.time, "time", lambda: real() + logbuffer._TTL_SEC + 10
    )
    assert logbuffer.entries() == []


def test_blank_lines_ignored():
    logbuffer.append("x", "   ")
    logbuffer.append("x", "")
    assert logbuffer.entries() == []


def test_long_line_truncated():
    logbuffer.append("x", "가" * 5000)
    assert len(logbuffer.entries()[0]["message"]) == 2000


def test_logging_handler_feeds_buffer():
    """파이썬 로깅과 nuclei 출력을 같은 버퍼에 모아 시간순으로 보여줌"""
    logbuffer.install()
    logging.getLogger("app.test").info("스캔 시작")
    assert any(i["message"] == "스캔 시작" for i in logbuffer.entries())


def test_install_is_idempotent():
    """재호출로 핸들러가 중복 부착되면 같은 줄이 여러 번 쌓임"""
    logbuffer.install()
    logbuffer.install()
    logbuffer.clear()
    logging.getLogger("app.test").info("한 번만")
    assert len([i for i in logbuffer.entries() if i["message"] == "한 번만"]) == 1


def test_download_returns_text_file(db_path):
    """서버는 저장하지 않는다. 사용자가 원할 때만 내보냄"""
    from fastapi.testclient import TestClient

    from app.main import app

    logbuffer.append("nuclei", "[CRITICAL] CVE-2026-33017 · RCE")
    with TestClient(app) as client:
        response = client.get("/api/v1/logs/download")

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "attachment" in response.headers["content-disposition"]
    assert "redar_log_" in response.headers["content-disposition"]
    assert "CVE-2026-33017" in response.text


def test_endpoint_returns_cursor(db_path):
    from fastapi.testclient import TestClient

    from app.main import app

    logbuffer.append("nuclei", "진행 중")
    with TestClient(app) as client:
        body = client.get("/api/v1/logs").json()
    assert body["items"]
    assert body["cursor"] == body["items"][-1]["seq"]

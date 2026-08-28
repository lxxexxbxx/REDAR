"""M3 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M3).

nuclei 는 실행하지 않고 JSONL 픽스처를 흘리는 러너를 주입
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.domain.allowlist import host_allowed, target_allowed
from app.main import app
from app.repository.db import session
from app.services import scan_service
from app.services.scan_service import ScanService


def _service(db_path, **kwargs) -> ScanService:
    """nuclei 미설치 환경용. 커맨드 조립·실행 둘 다 대체"""
    return ScanService(
        db_path,
        command_builder=lambda opts: ["fake-nuclei"],
        command_runner=_fixture_runner(**kwargs),
    )

FIXTURE = Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl"
API = "/api/v1"


def _fixture_runner(delay: float = 0.0, hang: bool = False):
    """nuclei 대체. 픽스처를 stdout 라인으로 흘리고 stats 를 stderr 로 낸다."""

    def run(command, *, on_stdout_line, on_stderr_line=None, cancel=None) -> int:
        for line in FIXTURE.read_text(encoding="utf-8").splitlines():
            if cancel is not None and cancel.is_set():
                return 1
            on_stdout_line(line)
            if delay:
                time.sleep(delay)
        if on_stderr_line is not None:
            on_stderr_line("[0:00:01] | Templates: 5 | Requests: 5/5 (100%)")
        while hang and not (cancel is not None and cancel.is_set()):
            time.sleep(0.02)
        return 0

    return run


@pytest.fixture
def client(db_path, monkeypatch):
    monkeypatch.setattr(
        "app.repository.db.settings.DB_PATH", db_path, raising=False
    )
    scan_service.set_service(_service(db_path))
    with TestClient(app) as test_client:
        yield test_client
    scan_service.set_service(None)


@pytest.fixture
def allowlisted(conn):
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('target_allowlist', ?)"
        " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (json.dumps(["localhost", "192.168.1.0/24"]),),
    )
    conn.commit()
    yield
    conn.execute(
        "UPDATE settings SET value = '[]' WHERE key = 'target_allowlist'"
    )
    conn.commit()


def _create(client: TestClient, targets: list[str]) -> Any:
    return client.post(
        f"{API}/scans",
        json={
            "targets": targets,
            "template_selection": {"mode": "filter", "tags": ["cve"]},
            "collect_environment": False,
        },
    )


def _wait_done(client: TestClient, scan_id: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"{API}/scans/{scan_id}").json()
        if body["status"] in ("completed", "failed", "canceled"):
            return body
        time.sleep(0.02)
    raise AssertionError("스캔이 끝나지 않음")


# ------------------------------------------------------------- allowlist


def test_allowlist_empty_blocks_everything():
    """기본값 비어 있음 = 전부 차단. 버그가 아니라 의도된 동작 (절대규칙 6)."""
    assert host_allowed("localhost", []) is False
    assert target_allowed("http://example.com", []) is False


@pytest.mark.parametrize(
    "target,allowed",
    [
        ("http://localhost:7860/x", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("http://192.168.1.50", True),      # CIDR 포함
        ("192.168.2.50", False),            # CIDR 밖
        ("http://evil.example.com", False),
        ("http://h:abc/", False),           # 해석 불가 대상은 차단
    ],
)
def test_allowlist_matching(target, allowed):
    assert target_allowed(target, ["localhost", "192.168.1.0/24"]) is allowed


def test_hostname_not_resolved_to_ip():
    """호스트명을 DNS 로 해석해 CIDR 대조하지 않음. 조회 자체가 아웃바운드 통신."""
    assert host_allowed("localhost", ["127.0.0.0/8"]) is False


def test_scan_rejected_when_target_not_allowlisted(client):
    response = _create(client, ["http://evil.example.com"])
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert "not allowed" in body["error"]["details"][0]["reason"]


# ------------------------------------------------------------- 오류 형식


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("get", f"{API}/scans/scn_nope", None),
        ("get", f"{API}/findings/fnd_nope", None),
        ("get", f"{API}/scans/scn_nope/findings", None),
        ("post", f"{API}/scans/scn_nope/cancel", None),
        ("delete", f"{API}/scans/scn_nope", None),
    ],
)
def test_not_found_uses_common_error_shape(client, method, path, payload):
    response = getattr(client, method)(path, **({"json": payload} if payload else {}))
    assert response.status_code == 404
    error = response.json()["error"]
    assert set(error) == {"code", "message", "details"}
    assert error["code"] == "NOT_FOUND"


def test_validation_error_uses_common_error_shape(client):
    response = client.post(f"{API}/scans", json={"targets": []})
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "INVALID_REQUEST"
    assert error["details"]


def test_environment_driven_requires_environment_collection(client, allowlisted):
    """환경 조사 없이 환경 기반 선별은 성립하지 않는다.

    filter 로 조용히 대체하면 보고서의 선별 근거가 사라진다 (M4)
    """
    response = client.post(
        f"{API}/scans",
        json={
            "targets": ["http://localhost:7860"],
            "template_selection": {"mode": "environment_driven"},
            "collect_environment": False,
        },
    )
    assert response.status_code == 400
    assert "collect_environment" in response.json()["error"]["message"]


def test_environment_driven_mode_accepted(client, allowlisted):
    """M4 부터 지원. 수집기가 대상에 닿지 못해도 스캔은 생성된다"""
    response = client.post(
        f"{API}/scans",
        json={
            "targets": ["http://localhost:7860"],
            "template_selection": {"mode": "environment_driven"},
        },
    )
    assert response.status_code == 202


# ------------------------------------------------------------- 스캔 실행


def test_scan_runs_and_stores_findings(client, allowlisted):
    response = _create(client, ["http://localhost:7860"])
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    assert response.json()["status"] in ("queued", "running")

    view = _wait_done(client, scan_id)
    assert view["status"] == "completed"
    assert view["finding_counts"]["critical"] == 1
    assert view["targets"] == ["http://localhost:7860"]

    findings = client.get(f"{API}/scans/{scan_id}/findings").json()
    assert findings["total"] == 4                 # 중복 1건 제외
    assert findings["items"][0]["severity"] == "critical"   # 심각도 정렬
    assert findings["aggregations"]["by_severity"]["critical"] == 1
    # 심각도 5종·유형 14종 축 고정
    assert len(findings["aggregations"]["by_severity"]) == 5
    assert len(findings["aggregations"]["by_vuln_type"]) == 14


def test_findings_filter_does_not_change_aggregations(client, allowlisted):
    scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
    _wait_done(client, scan_id)

    filtered = client.get(
        f"{API}/scans/{scan_id}/findings?severity=critical"
    ).json()
    assert filtered["total"] == 1
    # aggregations 는 필터 적용 전 전체 기준 (docs/00 §4)
    assert sum(filtered["aggregations"]["by_severity"].values()) == 4


def test_false_positive_excluded_from_aggregations(client, allowlisted):
    scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
    _wait_done(client, scan_id)

    findings = client.get(f"{API}/scans/{scan_id}/findings").json()["items"]
    critical = next(f for f in findings if f["severity"] == "critical")

    patched = client.patch(
        f"{API}/findings/{critical['finding_id']}",
        json={"status": "false_positive", "note": "인증 미들웨어로 보호됨"},
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "false_positive"

    after = client.get(f"{API}/scans/{scan_id}/findings").json()
    assert after["aggregations"]["by_severity"]["critical"] == 0
    assert sum(after["aggregations"]["by_severity"].values()) == 3
    # 목록에서는 사라지지 않음. 필터로 조회 가능
    assert after["total"] == 4
    assert client.get(f"{API}/scans/{scan_id}").json()["finding_counts"]["critical"] == 0


def test_finding_detail_includes_empty_guide_items(client, allowlisted):
    """가이드 본문 미탑재 시 빈 배열이 정상 (절대규칙 3)."""
    scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
    _wait_done(client, scan_id)
    finding_id = client.get(f"{API}/scans/{scan_id}/findings").json()["items"][0][
        "finding_id"
    ]
    detail = client.get(f"{API}/findings/{finding_id}").json()
    assert detail["guide_items"] == []
    assert detail["guide_refs"] == []
    assert detail["evidence"]["curl_command"].startswith("curl ")


def test_scan_list_and_delete(client, allowlisted):
    scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
    _wait_done(client, scan_id)

    listed = client.get(f"{API}/scans?status=completed").json()
    assert any(item["scan_id"] == scan_id for item in listed["items"])

    assert client.delete(f"{API}/scans/{scan_id}").status_code == 204
    assert client.get(f"{API}/scans/{scan_id}").status_code == 404
    with session() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchone()[0] == 0


def test_concurrent_scan_rejected(db_path, client, allowlisted):
    """동시 1건만. DB 쓰기 직렬화 목적 (docs/02 §5.3)."""
    scan_service.set_service(_service(db_path, hang=True))
    first = _create(client, ["http://localhost:7860"])
    assert first.status_code == 202
    try:
        second = _create(client, ["http://localhost:7860"])
        assert second.status_code == 409
        assert second.json()["error"]["code"] == "SCAN_ALREADY_RUNNING"
    finally:
        scan_service.get_service().cancel(first.json()["scan_id"])
        _wait_done(client, first.json()["scan_id"])


def test_cancel_preserves_stored_findings(db_path, client, allowlisted):
    """중단 시 이미 저장된 finding 보존."""
    scan_service.set_service(_service(db_path, hang=True))
    scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if client.get(f"{API}/scans/{scan_id}/findings").json()["total"] > 0:
            break
        time.sleep(0.02)

    assert client.post(f"{API}/scans/{scan_id}/cancel").status_code == 200
    view = _wait_done(client, scan_id)
    assert view["status"] == "canceled"
    assert client.get(f"{API}/scans/{scan_id}/findings").json()["total"] == 4


def test_findings_readable_while_scan_running(db_path, client, allowlisted):
    """스캔 중 조회 가능 (WAL 동작 확인)."""
    scan_service.set_service(_service(db_path, delay=0.05, hang=True))
    scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
    try:
        deadline = time.monotonic() + 5
        seen = 0
        while time.monotonic() < deadline:
            body = client.get(f"{API}/scans/{scan_id}").json()
            seen = client.get(f"{API}/scans/{scan_id}/findings").json()["total"]
            if body["status"] == "running" and seen > 0:
                break
            time.sleep(0.02)
        assert seen > 0
    finally:
        scan_service.get_service().cancel(scan_id)
        _wait_done(client, scan_id)


# ------------------------------------------------------------------- SSE


def test_sse_emits_progress_finding_done(db_path, allowlisted):
    """progress · finding · done 수신 확인."""
    service = _service(db_path, delay=0.02)
    scan_service.set_service(service)
    with TestClient(app) as client:
        scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]

        events: list[str] = []
        with client.stream("GET", f"{API}/scans/{scan_id}/stream") as stream:
            for line in stream.iter_lines():
                if line.startswith("event: "):
                    events.append(line[len("event: "):].strip())
                if events and events[-1] == "done":
                    break

    assert "progress" in events
    assert "finding" in events
    assert events[-1] == "done"


def test_finding_events_throttled_to_10_per_sec(db_path, allowlisted):
    """초당 10건 상한. 초과분은 이벤트만 생략되고 저장은 그대로."""
    service = _service(db_path)
    scan_service.set_service(service)
    with TestClient(app) as client:
        scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
        _wait_done(client, scan_id)
        events = list(service.events(scan_id, timeout=1.0))
    finding_events = [e for e, _ in events if e == "finding"]
    assert len(finding_events) <= 10


def test_sse_on_finished_scan_returns_done(db_path, client, allowlisted):
    """이미 끝난 스캔을 구독해도 무한 대기하지 않음."""
    scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
    _wait_done(client, scan_id)
    scan_service.set_service(_service(db_path))

    with client.stream("GET", f"{API}/scans/{scan_id}/stream") as stream:
        events = [
            line[len("event: "):].strip()
            for line in stream.iter_lines()
            if line.startswith("event: ")
        ]
    assert events == ["done"]


# -------------------------------------------------------------- 대상 파일


def test_target_file_import(client):
    content = b"http://localhost:7860\n\n# comment\n!!!bad\nlocalhost:8080,note\n"
    response = client.post(
        f"{API}/targets/import",
        files={"file": ("targets.txt", content, "text/plain")},
    )
    body = response.json()
    assert body["targets"] == ["http://localhost:7860", "localhost:8080"]
    assert body["count"] == 2
    assert body["invalid_lines"] == [4]


# ---------------------------------------------------------------- settings


def test_settings_roundtrip(client):
    initial = client.get(f"{API}/settings").json()
    assert initial["offline_mode"] is True
    assert initial["target_allowlist"] == []
    assert len(initial["external_endpoints"]) == 3

    updated = client.put(
        f"{API}/settings",
        json={
            "target_allowlist": ["localhost", " 10.0.0.0/8 "],
            "scan_defaults": {"threads": 40},
        },
    ).json()
    assert updated["target_allowlist"] == ["localhost", "10.0.0.0/8"]
    assert updated["scan_defaults"]["threads"] == 40
    assert updated["scan_defaults"]["timeout_sec"] == 10   # 미전송 항목 유지

    client.put(f"{API}/settings", json={"target_allowlist": []})


def test_offline_mode_forces_external_endpoints_off(client):
    client.put(
        f"{API}/settings",
        json={
            "offline_mode": True,
            "external_endpoints": [{"key": "template_sync", "enabled": True}],
        },
    )
    body = client.get(f"{API}/settings").json()
    sync = next(e for e in body["external_endpoints"] if e["key"] == "template_sync")
    assert sync["enabled"] is False       # 오프라인 모드가 강제 차단
    assert sync["configured"] is True     # 사용자 설정값은 보존

    body = client.put(f"{API}/settings", json={"offline_mode": False}).json()
    sync = next(e for e in body["external_endpoints"] if e["key"] == "template_sync")
    assert sync["enabled"] is True

    client.put(
        f"{API}/settings",
        json={
            "offline_mode": True,
            "external_endpoints": [{"key": "template_sync", "enabled": False}],
        },
    )


def test_unknown_external_endpoint_rejected(client):
    """목록 밖의 통신 지점을 설정으로 추가할 수 없음 (절대규칙 5)."""
    response = client.put(
        f"{API}/settings",
        json={"external_endpoints": [{"key": "telemetry", "enabled": True}]},
    )
    assert response.status_code == 400
    assert "telemetry" in response.json()["error"]["message"]


def test_settings_rejects_unknown_field(client):
    response = client.put(f"{API}/settings", json={"nope": 1})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_thread_safety_of_service_singleton():
    """set_service 로 주입한 인스턴스는 스레드에서도 동일"""
    seen: list[int] = []
    service = scan_service.get_service()

    def check() -> None:
        seen.append(id(scan_service.get_service()))

    workers = [threading.Thread(target=check) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert set(seen) == {id(service)}

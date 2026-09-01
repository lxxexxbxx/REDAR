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

from app.domain.allowlist import host_allowed, normalize_entry, target_allowed
from app.repository import settings_repo
from app.main import app
from app.repository.db import session
from app.services import scan_service
from app.services.scan_service import ScanService


def _service(db_path, prober=None, **kwargs) -> ScanService:
    """nuclei 미설치 환경용. 커맨드 조립·실행 둘 다 대체.

    prober 도 주입 대상이다. 기본값은 실제 소켓을 열어 CI 에서 대상에 접속하게 됨
    """
    return ScanService(
        db_path,
        command_builder=lambda opts: ["fake-nuclei"],
        command_runner=_fixture_runner(**kwargs),
        prober=prober or (lambda targets: list(targets)),
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


_SEED_TEMPLATE_ID = "seed-template"


def _set_seed_template(db_path, present: bool) -> None:
    """스캔 성립 조건. 템플릿 0개는 사전 점검에서 거부되므로 정상 경로 테스트에 필요.

    db_path 는 세션 스코프라 남겨두면 '템플릿 없음' 을 검증하는 테스트가 오염됨
    """
    with session(db_path) as conn:
        if present:
            conn.execute(
                "INSERT OR IGNORE INTO templates"
                " (template_id, source, file_path, name, severity)"
                " VALUES (?, 'custom', '/tmp/seed.yaml', 'seed', 'info')",
                (_SEED_TEMPLATE_ID,),
            )
        else:
            conn.execute(
                "DELETE FROM templates WHERE template_id = ?", (_SEED_TEMPLATE_ID,)
            )
        conn.commit()


@pytest.fixture
def scannable(db_path):
    """템플릿 보유 상태. 스캔을 실제로 시작하는 테스트가 사전 점검을 통과하려면 필요"""
    _set_seed_template(db_path, True)
    yield
    _set_seed_template(db_path, False)


@pytest.fixture
def client(db_path, scannable, monkeypatch):
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


def _create(client: TestClient, targets: list[str], **extra: Any) -> Any:
    return client.post(
        f"{API}/scans",
        json={
            "targets": targets,
            "template_selection": {"mode": "filter", "tags": ["cve"]},
            "collect_environment": False,
            **extra,
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


@pytest.mark.parametrize(
    "entry,target",
    [
        ("http://localhost", "localhost"),
        ("http://localhost", "http://localhost:7860/x"),
        ("https://target.local:8443/admin", "target.local"),
        ("  HTTP://Target.Local/  ", "http://target.local:9000"),
    ],
)
def test_url_shaped_allowlist_entry_matches(entry, target):
    """사용자는 URL 을 그대로 붙여넣음. 호스트로 정규화하지 않으면 영영 매칭 안 됨"""
    assert target_allowed(target, [entry]) is True


def test_normalize_keeps_cidr_and_rejects_garbage():
    assert normalize_entry("192.168.1.0/24") == "192.168.1.0/24"
    assert normalize_entry("  ") == ""
    # 해석 불가 값은 통과시키지 않음
    assert target_allowed("evil.com", [normalize_entry("!!!")]) is False


def test_allowlist_save_normalizes_and_dedupes(client):
    """저장 시점에 정규화. 같은 호스트를 다른 표기로 넣어도 한 줄"""
    saved = client.put(
        f"{API}/settings",
        json={"target_allowlist": ["http://localhost:7860", "LOCALHOST", " "]},
    )
    assert saved.status_code == 200
    assert saved.json()["target_allowlist"] == ["localhost"]
    client.put(f"{API}/settings", json={"target_allowlist": []})


def test_hostname_not_resolved_to_ip():
    """호스트명을 DNS 로 해석해 CIDR 대조하지 않음. 조회 자체가 아웃바운드 통신."""
    assert host_allowed("localhost", ["127.0.0.0/8"]) is False


def test_scan_registers_typed_target(client, conn):
    """스캔 화면 입력이 곧 동의. 같은 값을 설정에 한 번 더 적게 하지 않음
    (절대규칙 6 개정). 등록 결과는 목록에 남아 추적 가능해야 함"""
    response = _create(client, ["http://evil.example.com"])
    assert response.status_code == 202
    assert response.json()["auto_allowed"] == ["evil.example.com"]
    # 호스트로 정규화되어 저장됨
    assert "evil.example.com" in settings_repo.target_allowlist(conn)
    conn.execute("UPDATE settings SET value = '[]' WHERE key = 'target_allowlist'")
    conn.commit()


def test_already_allowed_target_not_reported_as_added(client, allowlisted):
    """이미 있는 대상을 다시 스캔할 때 '추가됨' 으로 알리면 거짓 알림"""
    response = _create(client, ["localhost"])
    assert response.status_code == 202
    assert response.json()["auto_allowed"] == []


def test_gate_still_applies_outside_scan_screen(conn):
    """게이트를 스캔 화면 경로에서만 열었다. 판정 함수 자체는 그대로여야 함"""
    assert target_allowed("evil.example.com", []) is False
    assert target_allowed("evil.example.com", ["localhost"]) is False


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
    """환경 조사 없이 환경 기반 선별은 성립하지 않음

    filter 로 조용히 대체하면 보고서의 선별 근거가 사라짐 (M4)
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
    """M4 부터 지원. 수집기가 대상에 닿지 못해도 스캔은 생성됨"""
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


def test_finding_detail_maps_without_guide_body(client, allowlisted):
    """본문 미탑재 시 guide_items 는 빈 배열, 매핑은 남음 (절대규칙 3)."""
    scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
    _wait_done(client, scan_id)
    finding_id = client.get(f"{API}/scans/{scan_id}/findings").json()["items"][0][
        "finding_id"
    ]
    detail = client.get(f"{API}/findings/{finding_id}").json()
    assert detail["guide_items"] == []          # 본문 없음
    assert detail["guide_refs"]                 # 매핑은 저장됨 (M6)
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


def test_sse_emits_progress_finding_done(db_path, allowlisted, scannable):
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


def test_finding_events_throttled_to_10_per_sec(db_path, allowlisted, scannable):
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
    # 통신 지점 4곳: 템플릿 갱신 · LLM · CVE 조회 · 의존성 자동 설치
    assert len(initial["external_endpoints"]) == 4

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


# ------------------------------------------------------------- 사전 점검

def test_preflight_blocks_when_no_templates(conn, allowlisted, monkeypatch):
    """템플릿 0개면 nuclei 가 아무것도 실행하지 않고 성공으로 끝나
    '탐지 0건' 이 '양호' 로 오독됨 (절대규칙 10)"""
    monkeypatch.setattr(scan_service.settings, "nuclei_bin", lambda: "/tmp/nuclei")
    monkeypatch.setattr(scan_service.settings, "nuclei_template_store", lambda: None)
    result = scan_service.preflight(conn)
    assert result["ready"] is False
    blocker = next(b for b in result["blockers"] if b["code"] == "NO_TEMPLATES")
    # 막힌 사실만으로는 부족. 다음 행동과 이동할 화면을 알려줘야 함
    assert blocker["action"]
    assert blocker["goto"] == "templates"


def test_preflight_accepts_nuclei_own_store(conn, allowlisted, monkeypatch):
    """REDAR 색인이 비어도 사용자가 nuclei 로 직접 받아뒀으면 스캔 성립"""
    monkeypatch.setattr(scan_service.settings, "nuclei_bin", lambda: "/tmp/nuclei")
    monkeypatch.setattr(
        scan_service.settings, "nuclei_template_store",
        lambda: "/home/u/nuclei-templates",
    )
    result = scan_service.preflight(conn)
    assert result["blockers"] == []
    assert result["ready"] is True


def test_preflight_reports_every_blocker(conn, monkeypatch):
    """하나씩 알려주면 고치고 또 막힘. 남은 것을 한 번에 보여줘야 함"""
    monkeypatch.setattr(scan_service.settings, "nuclei_bin", lambda: None)
    monkeypatch.setattr(scan_service.settings, "nuclei_template_store", lambda: None)
    codes = {b["code"] for b in scan_service.preflight(conn)["blockers"]}
    # 허용 목록 비어 있음은 더 이상 차단 사유가 아니다. 스캔 화면 입력이 곧 등록이라
    # 여기서 막으면 첫 스캔을 시작할 방법이 없음 (절대규칙 6 개정)
    assert codes == {"NUCLEI_MISSING", "NO_TEMPLATES"}


def test_scan_rejected_without_templates(client, conn, allowlisted, monkeypatch):
    """조용히 0건으로 끝나지 않고 이유를 밝히며 거부"""
    monkeypatch.setattr(scan_service.settings, "nuclei_template_store", lambda: None)
    conn.execute("DELETE FROM templates")
    conn.commit()
    response = _create(client, ["localhost"])
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "NO_TEMPLATES"


# ------------------------------------------------------------- 포트 범위

def test_port_range_expands_and_keeps_input(client, allowlisted):
    """실행은 개별 포트, 표기는 입력 원문. 두 층이 함께 남아야 함"""
    scan_id = _create(client, ["localhost:7860-7862"]).json()["scan_id"]
    _wait_done(client, scan_id)

    view = client.get(f"{API}/scans/{scan_id}").json()
    assert view["target_input"] == ["localhost:7860-7862"]
    assert view["targets"] == ["localhost:7860", "localhost:7861", "localhost:7862"]


def test_large_range_needs_confirmation(client, allowlisted):
    """대상이 곱으로 늘어 부하가 큼. 조용히 진행하지 않고 되물음"""
    ports = scan_service.target_range.CONFIRM_THRESHOLD + 2
    response = _create(client, [f"localhost:1000-{1000 + ports}"])
    assert response.status_code == 400
    body = response.json()["error"]
    assert body["code"] == "LARGE_TARGET_EXPANSION"
    assert str(ports + 1) in body["message"]        # 몇 건인지 알려줘야 함


def test_large_range_proceeds_once_confirmed(client, allowlisted):
    ports = scan_service.target_range.CONFIRM_THRESHOLD + 2
    response = _create(
        client, [f"localhost:1000-{1000 + ports}"], confirm_expanded=True
    )
    assert response.status_code == 202


def test_small_range_does_not_ask(client, allowlisted):
    """상한 이하는 되묻지 않음. 매번 확인창이 뜨면 확인이 무의미해짐"""
    assert _create(client, ["localhost:7860-7862"]).status_code == 202


def test_range_over_max_rejected(client, allowlisted):
    over = scan_service.target_range.MAX_PORTS + 1
    response = _create(client, [f"localhost:1-{over}"], confirm_expanded=True)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_range_registers_host_once(client, conn):
    """범위 표기도 호스트 기준. 401개 포트를 목록에 401줄로 넣으면 안 됨"""
    try:
        response = _create(client, ["target.local:7860-7862"])
        assert response.status_code == 202
        assert response.json()["auto_allowed"] == ["target.local"]
        assert settings_repo.target_allowlist(conn) == ["target.local"]
    finally:
        conn.execute("UPDATE settings SET value = '[]' WHERE key = 'target_allowlist'")
        conn.commit()


def test_already_allowed_range_not_reregistered(client, conn, allowlisted):
    """localhost 가 이미 있으면 포트 범위로 다시 스캔해도 추가 없음"""
    response = _create(client, ["localhost:7860-7862"])
    assert response.status_code == 202
    assert response.json()["auto_allowed"] == []


# ------------------------------------------------------------- 처리 로그

def test_findings_appear_in_log(db_path, allowlisted, scannable):
    """탐지 결과는 stdout 으로 온다. 로그에 넣지 않으면 진행률만 찍혀
    '무엇이 잡혔는지' 를 로그에서 볼 수 없음"""
    from app.adapters import logbuffer

    logbuffer.clear()
    scan_service.set_service(_service(db_path))
    with TestClient(app) as client:
        scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
        _wait_done(client, scan_id)
    scan_service.set_service(None)

    found = [i for i in logbuffer.entries() if i["source"] == "탐지"]
    assert found, "탐지 줄이 로그에 있어야 함"
    # 심각도와 대상이 함께 보여야 어떤 항목인지 알 수 있음
    assert any("[" in i["message"] and "→" in i["message"] for i in found)


def test_executed_command_logged(db_path, allowlisted, scannable):
    """'왜 안 잡혔나' 는 무엇을 실행했는지 모르면 답할 수 없음"""
    from app.adapters import logbuffer

    logbuffer.clear()
    scan_service.set_service(_service(db_path))
    with TestClient(app) as client:
        scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
        _wait_done(client, scan_id)
    scan_service.set_service(None)

    assert any("nuclei 실행" in i["message"] for i in logbuffer.entries())


def test_stats_line_is_readable():
    """원문 JSON 은 한 줄이 길어 읽히지 않음"""
    from app.adapters.nuclei.progress import Progress

    line = scan_service._stats_line(
        Progress(percent=46, requests_done=8843, requests_total=19000, errors=41), 3
    )
    assert "46%" in line
    assert "8843/19000" in line
    assert "탐지 3건" in line
    assert "오류 41건" in line
    assert "{" not in line


# ------------------------------------------------------------- 템플릿 선별 범위

def test_id_and_tags_never_sent_together():
    """nuclei 는 서로 다른 필터를 AND 로 묶는다. 둘 다 주면 교집합만 남아
    의도한 것보다 훨씬 적게 실행됨. 조립 단계에서 막아야 함"""
    from app.adapters.nuclei import runner

    with pytest.raises(ValueError):
        runner.build_command(
            runner.RunOptions(
                targets=["localhost"], template_ids=["a"], tags=["wordpress"],
            ),
            exe="/tmp/nuclei",
        )


def test_environment_mode_runs_all_templates(conn):
    """환경 조사로 범위를 좁히지 않는다. 진단 도구에서 선별로 놓치는 것은
    시간을 아끼는 것보다 나쁨"""
    from app.services import environment_service

    result = environment_service.EnvironmentResult(
        profile_id="env_x", target_host="wp.local",
        stack={"application": {"product": "WordPress", "version": "6.4.2"}},
        components=[{"type": "wp_plugin", "slug": "contact-form-7",
                     "version": "5.9", "confidence": "high"}],
    )
    selection = environment_service.select_templates(conn, [result])

    assert selection.template_ids == []
    assert selection.tags == []
    assert selection.basis["filtered"] is False
    # 환경 근거는 남아야 보고서가 무엇을 봤는지 설명할 수 있음
    assert selection.basis["matched_stack"][0]["product"] == "WordPress"


# ------------------------------------------------------------- 대상 응답 확인

def test_unreachable_targets_excluded_and_recorded(db_path, allowlisted, scannable):
    """닫힌 포트는 스캔하지 않되, 건너뛴 사실은 남아야 함 (절대규칙 10)"""
    alive = "localhost:7861"
    scan_service.set_service(
        _service(db_path, prober=lambda targets: [t for t in targets if t == alive])
    )
    with TestClient(app) as client:
        scan_id = _create(client, ["localhost:7860-7862"]).json()["scan_id"]
        _wait_done(client, scan_id)
        view = client.get(f"{API}/scans/{scan_id}").json()

    probe = view["target_probe"]
    assert probe["requested"] == 3
    assert probe["responded"] == [alive]
    assert set(probe["no_response"]) == {"localhost:7860", "localhost:7862"}
    scan_service.set_service(None)


def test_all_unreachable_fails_loudly(db_path, allowlisted, scannable):
    """전부 무응답인데 '탐지 0건 완료' 로 끝나면 양호로 오독됨"""
    scan_service.set_service(_service(db_path, prober=lambda targets: []))
    with TestClient(app) as client:
        scan_id = _create(client, ["localhost:7860-7862"]).json()["scan_id"]
        view = _wait_done(client, scan_id)

    assert view["status"] == "failed"
    assert view["error"]["code"] == "NO_REACHABLE_TARGET"
    scan_service.set_service(None)


def test_probe_failure_does_not_block_scan(db_path, allowlisted, scannable):
    """사전 확인이 깨져도 스캔 자체는 진행. 보조 단계가 본 기능을 막으면 안 됨"""
    def broken(targets):
        raise OSError("probe down")

    scan_service.set_service(_service(db_path, prober=broken))
    with TestClient(app) as client:
        scan_id = _create(client, ["http://localhost:7860"]).json()["scan_id"]
        view = _wait_done(client, scan_id)

    assert view["status"] == "completed"
    scan_service.set_service(None)


def test_preflight_route_not_shadowed(client):
    """/scans/{scan_id} 가 먼저 잡으면 preflight 가 404 로 사라짐"""
    response = client.get(f"{API}/scans/preflight")
    assert response.status_code == 200
    assert "blockers" in response.json()

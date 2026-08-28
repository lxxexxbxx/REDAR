"""M8 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M8).

명명 규칙: fixed / still_vulnerable 이 아니라 resolved / persisted.
도구는 조치 성공 여부를 판정하지 않는다
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.domain.enums import CompareState
from app.domain.fingerprint import make_fingerprint
from app.main import app
from app.services import compare_service
from app.services.scan_service import ScanError

API = "/api/v1"


def _scan(conn, scan_id: str, findings: list[tuple[str, str, str]]) -> str:
    """findings: (finding_id, fingerprint, severity)"""
    conn.execute(
        "INSERT OR REPLACE INTO scans (scan_id, status, selection_mode,"
        " collect_environment, started_at) VALUES (?, 'completed', 'filter', 1, ?)",
        (scan_id, f"2026-08-2{scan_id[-1]} 10:00:00"),
    )
    conn.execute(
        "INSERT OR REPLACE INTO scan_targets (scan_id, raw, scheme, host, port)"
        " VALUES (?, 'http://wp.local', 'http', 'wp.local', 80)",
        (scan_id,),
    )
    for finding_id, fingerprint, severity in findings:
        conn.execute(
            "INSERT OR REPLACE INTO findings (finding_id, scan_id, fingerprint,"
            " template_id, target_raw, target_host, name, severity, severity_guide)"
            " VALUES (?, ?, ?, 'tpl-x', 'http://wp.local/x', 'wp.local', ?, ?, '상')",
            (finding_id, scan_id, fingerprint, f"탐지 {fingerprint}", severity),
        )
    conn.commit()
    return scan_id


@pytest.fixture
def pair(conn):
    base = _scan(conn, "scn_c1", [
        ("fnd_c1a", "fp_shared", "high"),
        ("fnd_c1b", "fp_gone", "critical"),
    ])
    target = _scan(conn, "scn_c2", [
        ("fnd_c2a", "fp_shared", "high"),
        ("fnd_c2b", "fp_new", "medium"),
    ])
    yield base, target
    for scan_id in ("scn_c1", "scn_c2"):
        conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM environment_profiles WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    conn.commit()


# ─────────────────────────────── 3분류 (완료 조건 1)

def test_three_way_classification(conn, pair):
    base, target = pair
    result = compare_service.compare(conn, base, target)

    assert result["summary"] == {"resolved": 1, "persisted": 1, "emerged": 1}
    assert [e["fingerprint"] for e in result["resolved"]] == ["fp_gone"]
    assert [e["fingerprint"] for e in result["persisted"]] == ["fp_shared"]
    assert [e["fingerprint"] for e in result["emerged"]] == ["fp_new"]


def test_persisted_carries_both_finding_ids(conn, pair):
    base, target = pair
    entry = compare_service.compare(conn, base, target)["persisted"][0]
    assert entry["base_finding_id"] == "fnd_c1a"
    assert entry["target_finding_id"] == "fnd_c2a"


def test_naming_uses_resolved_not_fixed(conn, pair):
    """조치 성공 판정처럼 읽히는 이름을 쓰지 않는다"""
    base, target = pair
    result = compare_service.compare(conn, base, target)
    assert set(result["summary"]) == {s.value for s in CompareState}
    assert "fixed" not in result
    assert "still_vulnerable" not in result


def test_false_positive_excluded(conn, pair):
    base, target = pair
    conn.execute(
        "UPDATE findings SET status = 'false_positive' WHERE finding_id = 'fnd_c1b'"
    )
    conn.commit()
    result = compare_service.compare(conn, base, target)
    # 오탐은 집계에서 빠졌으므로 '미탐지' 로도 나오지 않는다
    assert result["summary"]["resolved"] == 0


# ─────────────────────────────── 쿼리스트링 (완료 조건 2)

def test_query_string_does_not_cause_misclassification(conn):
    """fingerprint 가 쿼리스트링을 제외하므로 파라미터 차이는 같은 항목이다"""
    first = make_fingerprint("tpl-x", "wp.local", 80, "/search?q=1", "m0")
    second = make_fingerprint("tpl-x", "wp.local", 80, "/search?q=99&page=2", "m0")
    assert first == second

    base = _scan(conn, "scn_q1", [("fnd_q1", first, "high")])
    target = _scan(conn, "scn_q2", [("fnd_q2", second, "high")])
    try:
        result = compare_service.compare(conn, base, target)
        assert result["summary"] == {"resolved": 0, "persisted": 1, "emerged": 0}
    finally:
        for scan_id in ("scn_q1", "scn_q2"):
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()


# ─────────────────────────────── disclaimer (완료 조건 3)

def test_disclaimer_always_present(conn, pair):
    base, target = pair
    result = compare_service.compare(conn, base, target)
    assert "미탐지는 조치 완료를 보장하지 않습니다" in result["disclaimer"]


def test_disclaimer_present_when_no_difference(conn):
    base = _scan(conn, "scn_s1", [("fnd_s1", "fp_same", "low")])
    target = _scan(conn, "scn_s2", [("fnd_s2", "fp_same", "low")])
    try:
        result = compare_service.compare(conn, base, target)
        assert result["summary"] == {"resolved": 0, "persisted": 1, "emerged": 0}
        assert result["disclaimer"]
    finally:
        for scan_id in ("scn_s1", "scn_s2"):
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()


# ─────────────────────────────── environment_diff

def _add_env(conn, scan_id, profile_id, *, version, exposure):
    conn.execute(
        "INSERT OR REPLACE INTO environment_profiles (profile_id, scan_id,"
        " target_host, application_product, application_version,"
        " application_confidence) VALUES (?, ?, 'wp.local', 'WordPress', ?, 'high')",
        (profile_id, scan_id, version),
    )
    conn.execute("DELETE FROM env_exposures WHERE profile_id = ?", (profile_id,))
    conn.execute(
        "INSERT INTO env_exposures (profile_id, key, value, path)"
        " VALUES (?, 'xmlrpc_enabled', ?, '/xmlrpc.php')",
        (profile_id, int(exposure)),
    )
    conn.commit()


def test_environment_diff_reports_version_change(conn, pair):
    base, target = pair
    _add_env(conn, base, "env_c1", version="6.4.2", exposure=True)
    _add_env(conn, target, "env_c2", version="6.7.1", exposure=False)

    diff = compare_service.compare(conn, base, target)["environment_diff"]
    changed = {c["key"]: (c["before"], c["after"]) for c in diff["changed"]}
    assert changed["application.version"] == ("6.4.2", "6.7.1")
    assert changed["exposures.xmlrpc_enabled"] == (True, False)


def test_environment_diff_empty_when_no_profiles(conn, pair):
    base, target = pair
    diff = compare_service.compare(conn, base, target)["environment_diff"]
    assert diff == {"changed": [], "added": [], "removed": []}


# ─────────────────────────────── 오류 처리 · 라우팅

def test_missing_scan_is_404(conn, pair):
    base, _ = pair
    with pytest.raises(ScanError) as exc:
        compare_service.compare(conn, base, "scn_nope")
    assert exc.value.status_code == 404


def test_same_scan_rejected(conn, pair):
    base, _ = pair
    with pytest.raises(ScanError) as exc:
        compare_service.compare(conn, base, base)
    assert exc.value.status_code == 400


def test_compare_route_not_shadowed_by_scan_id(db_path, monkeypatch):
    """/scans/compare 가 /scans/{scan_id} 로 해석되면 404 가 된다"""
    monkeypatch.setattr("app.repository.db.settings.DB_PATH", db_path, raising=False)
    with TestClient(app) as client:
        response = client.get(f"{API}/scans/compare?base=scn_x&target=scn_y")
    assert response.status_code == 404
    # scan_id 로 오해석되면 'compare' 를 못 찾는다는 메시지가 나온다
    assert "scn_x" in response.json()["error"]["message"]


def test_compare_endpoint_returns_full_shape(db_path, monkeypatch, conn, pair):
    base, target = pair
    monkeypatch.setattr("app.repository.db.settings.DB_PATH", db_path, raising=False)
    with TestClient(app) as client:
        body = client.get(f"{API}/scans/compare?base={base}&target={target}").json()

    assert set(body) == {
        "base_scan", "target_scan", "summary", "resolved", "persisted",
        "emerged", "environment_diff", "disclaimer",
    }
    assert body["base_scan"]["total"] == 2
    assert body["target_scan"]["total"] == 2


def test_report_does_not_include_comparison(conn, pair):
    """비교는 이 API 전용이다. 보고서 골격에 들어가지 않는다 (docs/04 §2)"""
    from app.report import builder

    base, _ = pair
    report = builder.build(conn, base, report_id="rpt_x")
    for key in report:
        assert "compare" not in key
    assert "resolved" not in report

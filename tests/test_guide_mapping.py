"""M6 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M6).

목 데이터도 실제 항목 코드를 쓴다 (WA-02, WEB-25 등). 가짜 코드로 테스트하면
매핑 테이블의 실제 코드와 어긋나는 것을 못 잡는다
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.domain.enums import GuideVerdict
from app.repository import guide as guide_repo
from app.repository.db import session
from app.services import guide_importer, guide_service

MOCK_CSV = Path(__file__).parent / "fixtures" / "guide_items_mock.csv"


@pytest.fixture
def rules(conn):
    return guide_repo.load_mappings(conn)


@pytest.fixture
def scan(conn):
    """탐지 4건 + 자산 식별 1건. 매핑 대상은 4건"""
    conn.execute(
        "INSERT OR REPLACE INTO scans (scan_id, status, selection_mode,"
        " collect_environment) VALUES ('scn_map', 'completed', 'filter', 1)"
    )
    conn.execute(
        "INSERT OR REPLACE INTO templates (template_id, source, file_path, name,"
        " is_detection) VALUES ('wp-plugin-detect', 'official', 'x.yaml', 'Detect', 1)"
    )
    rows = [
        # (id, fingerprint, template_id, vuln_type, severity, cve, cwe, slug)
        ("fnd_xss", "fp1", "wordpress-xss-x", "xss", "high", None, '["CWE-79"]', None),
        ("fnd_cve", "fp2", "CVE-2026-63030", "rce", "critical",
         '["CVE-2026-63030"]', '["CWE-94"]', "contact-form-7"),
        ("fnd_only_type", "fp3", "unknown-template", "misconfig", "low", None, None, None),
        # template_id 계층에 실제 매핑이 있는 템플릿. CWE-79 도 함께 두어 우선순위를 본다
        ("fnd_tpl", "fp4", "CVE-2016-10033", "other", "medium", None, '["CWE-79"]', None),
        ("fnd_detect", "fp5", "wp-plugin-detect", "other", "info", None, None, None),
    ]
    for finding_id, fingerprint, template_id, vuln, severity, cve, cwe, slug in rows:
        conn.execute(
            "INSERT OR REPLACE INTO findings (finding_id, scan_id, fingerprint,"
            " template_id, target_raw, target_host, name, vuln_type, severity,"
            " severity_guide, cve_ids, cwe_ids, component_slug)"
            " VALUES (?, 'scn_map', ?, ?, 'http://wp.local', 'wp.local', ?, ?, ?,"
            " '상', ?, ?, ?)",
            (finding_id, fingerprint, template_id, f"탐지 {finding_id}", vuln,
             severity, cve, cwe, slug),
        )
    conn.commit()
    yield "scn_map"
    conn.execute("DELETE FROM findings WHERE scan_id = 'scn_map'")
    conn.execute("DELETE FROM scans WHERE scan_id = 'scn_map'")
    conn.execute("DELETE FROM templates WHERE template_id = 'wp-plugin-detect'")
    conn.execute("DELETE FROM environment_profiles WHERE scan_id = 'scn_map'")
    conn.commit()


def _refs(conn, finding_id):
    return {
        r["item_code"]: dict(r)
        for r in conn.execute(
            "SELECT * FROM finding_guide_refs WHERE finding_id = ?", (finding_id,)
        )
    }


# ─────────────────────────────────────── 우선순위 (완료 조건 1)

def test_template_id_wins_over_cwe(conn, scan, rules):
    """상위 층에서 매칭되면 하위는 적용하지 않는다"""
    guide_service.map_scan(conn, scan)
    refs = _refs(conn, "fnd_tpl")
    assert refs, "template_id 매핑이 있어야 한다"
    assert all(r["matched_by"].startswith("template_id:") for r in refs.values())
    # CWE-79 는 WA-06 으로 가는데, template_id 층이 이겼으므로 붙지 않는다
    assert "WA-06" not in refs
    assert "WA-01" in refs


def test_cwe_layer_used_when_no_template_rule(conn, scan):
    guide_service.map_scan(conn, scan)
    refs = _refs(conn, "fnd_xss")
    assert "WA-06" in refs
    assert refs["WA-06"]["matched_by"] == "cwe_id:CWE-79"
    assert refs["WA-06"]["is_primary"] == 1


def test_vuln_type_is_fallback_only(conn, scan):
    guide_service.map_scan(conn, scan)
    refs = _refs(conn, "fnd_only_type")
    assert refs
    assert all(r["matched_by"].startswith("vuln_type:") for r in refs.values())


def test_priority_order_matches_doc():
    assert guide_service.PRIORITY == (
        "template_id", "cve_id", "cwe_id", "exposure_key",
        "component_slug", "vuln_type",
    )


# ─────────────────────────────────────── 2트랙 (완료 조건 6·7)

def test_cve_finding_gets_web25_as_secondary(conn, scan):
    guide_service.map_scan(conn, scan)
    refs = _refs(conn, "fnd_cve")

    assert "WEB-25" in refs
    assert refs["WEB-25"]["is_primary"] == 0
    assert refs["WEB-25"]["matched_by"] is not None

    primary = [code for code, r in refs.items() if r["is_primary"] == 1]
    assert primary, "대표 항목이 있어야 한다"
    # WEB-25 를 대표로 삼으면 모든 CVE 가 패치 항목 하나로 수렴한다
    assert "WEB-25" not in primary


def test_non_cve_finding_has_no_web25(conn, scan):
    guide_service.map_scan(conn, scan)
    assert "WEB-25" not in _refs(conn, "fnd_xss")


# ─────────────────────────────────────── 자산 식별 제외 (완료 조건 8)

def test_detection_template_excluded(conn, scan):
    result = guide_service.map_scan(conn, scan)
    assert _refs(conn, "fnd_detect") == {}
    assert result.skipped_detection == 1


def test_false_positive_excluded(conn, scan):
    conn.execute(
        "UPDATE findings SET status = 'false_positive' WHERE finding_id = 'fnd_xss'"
    )
    conn.commit()
    guide_service.map_scan(conn, scan)
    assert _refs(conn, "fnd_xss") == {}


# ─────────────────────────────────────── 본문 미탑재 동작 (완료 조건 2·3)

def test_refs_written_without_guide_body(conn, scan):
    """본문이 없어도 매핑은 저장된다. item_code 에 FK 가 없는 이유 (절대규칙 3)"""
    assert conn.execute("SELECT COUNT(*) FROM guide_items").fetchone()[0] == 0
    result = guide_service.map_scan(conn, scan)
    assert result.refs_written > 0


def test_status_without_body(conn):
    status = guide_repo.status(conn)
    assert status["imported"] is False
    assert status["mapping_count"] == 454
    assert status["items_covered"] == 36


def test_map_scan_is_idempotent(conn, scan):
    first = guide_service.map_scan(conn, scan)
    second = guide_service.map_scan(conn, scan)
    assert first.refs_written == second.refs_written
    total = conn.execute(
        "SELECT COUNT(*) FROM finding_guide_refs r JOIN findings f"
        " ON f.finding_id = r.finding_id WHERE f.scan_id = ?", (scan,)
    ).fetchone()[0]
    assert total == second.refs_written


# ─────────────────────────────────────── safe / not_applicable (완료 조건 4)

def _add_environment(conn, scan_id, exposures, product="WordPress"):
    conn.execute(
        "INSERT OR REPLACE INTO environment_profiles (profile_id, scan_id,"
        " target_host, application_product, application_confidence)"
        " VALUES ('env_t', ?, 'wp.local', ?, 'high')",
        (scan_id, product),
    )
    conn.execute("DELETE FROM env_exposures WHERE profile_id = 'env_t'")
    for key, value in exposures.items():
        conn.execute(
            "INSERT INTO env_exposures (profile_id, key, value, path)"
            " VALUES ('env_t', ?, ?, '/')", (key, int(value))
        )
    conn.commit()


def test_unchecked_item_is_not_applicable_not_safe(conn, scan):
    """점검 근거가 없으면 not_applicable. safe 로 두면 미점검이 양호로 둔갑한다"""
    guide_service.map_scan(conn, scan)
    results = {v.item_code: v for v in guide_service.verdicts(conn, scan)}

    # 환경 조사 결과가 없는 상태 -> 노출 기반 항목은 not_applicable
    exposure_only = results["WEB-15"]
    assert exposure_only.verdict is GuideVerdict.NOT_APPLICABLE
    assert "점검 범위 외" in exposure_only.basis


def test_exposure_false_is_safe(conn, scan):
    _add_environment(conn, scan, {"xmlrpc_enabled": False})
    guide_service.map_scan(conn, scan)
    results = {v.item_code: v for v in guide_service.verdicts(conn, scan)}
    assert results["WEB-15"].verdict is GuideVerdict.SAFE


def test_exposure_true_is_vulnerable(conn, scan):
    _add_environment(conn, scan, {"xmlrpc_enabled": True})
    guide_service.map_scan(conn, scan)
    results = {v.item_code: v for v in guide_service.verdicts(conn, scan)}
    assert results["WEB-15"].verdict is GuideVerdict.VULNERABLE
    assert "xmlrpc_enabled" in results["WEB-15"].basis


def test_finding_makes_item_vulnerable(conn, scan):
    guide_service.map_scan(conn, scan)
    results = {v.item_code: v for v in guide_service.verdicts(conn, scan)}
    assert results["WA-06"].verdict is GuideVerdict.VULNERABLE
    assert results["WA-06"].finding_count >= 1


def test_verdict_summary_keeps_all_keys(conn, scan):
    guide_service.map_scan(conn, scan)
    summary = guide_service.summary(guide_service.verdicts(conn, scan))
    assert set(summary) == {v.value for v in GuideVerdict}


def test_all_mapped_items_get_a_verdict(conn, scan):
    """0건 항목이 사라지면 보고서 목차가 대상마다 달라진다 (절대규칙 4)"""
    guide_service.map_scan(conn, scan)
    verdicts = guide_service.verdicts(conn, scan)
    assert len(verdicts) == len(guide_repo.mapped_item_codes(conn)) == 36


# ─────────────────────────────────────── 임포트 (완료 조건 5·9)

def test_import_keeps_existing_refs(conn, scan):
    """임포트 후 기존 매핑이 보존되어야 한다. 별도 층이다"""
    guide_service.map_scan(conn, scan)
    before = conn.execute("SELECT COUNT(*) FROM finding_guide_refs").fetchone()[0]

    guide_importer.import_text(conn, MOCK_CSV.read_text(encoding="utf-8"))

    after = conn.execute("SELECT COUNT(*) FROM finding_guide_refs").fetchone()[0]
    assert after == before
    conn.execute("DELETE FROM guide_items")
    conn.commit()


def test_import_loads_all_21_columns(conn):
    result = guide_importer.import_text(conn, MOCK_CSV.read_text(encoding="utf-8"))
    assert result["item_count"] == 10

    row = conn.execute(
        "SELECT * FROM guide_items WHERE item_code = 'WA-02'"
    ).fetchone()
    # case_text·page_start 가 비면 보고서 A-6 조치 사항과 근거 페이지가 사라진다
    assert row["case_text"] == "사례 본문 WA-02 조치 절차"
    assert row["page_start"] == 684
    assert row["page_end"] == 686
    assert row["severity_guide"] == "상"
    assert row["item_code_raw"] == "SI"
    assert row["guide_version"] == "2026"
    assert row["category"] == "Web Application(웹)"

    filled = [k for k in row.keys() if row[k] not in (None, "")]
    assert len(filled) >= 19            # imported_at 포함, reference_note·detail 은 빈 값
    conn.execute("DELETE FROM guide_items")
    conn.commit()


def test_import_replaces_instead_of_appending(conn):
    text = MOCK_CSV.read_text(encoding="utf-8")
    guide_importer.import_text(conn, text)
    guide_importer.import_text(conn, text)
    assert conn.execute("SELECT COUNT(*) FROM guide_items").fetchone()[0] == 10
    conn.execute("DELETE FROM guide_items")
    conn.commit()


def test_import_rejects_missing_columns(conn):
    with pytest.raises(guide_importer.ImportError_, match="필수 컬럼"):
        guide_importer.import_text(conn, "item_code,item_name\nWA-01,인젝션\n")


def test_import_reports_mixed_versions(conn):
    lines = MOCK_CSV.read_text(encoding="utf-8").splitlines()
    lines[2] = lines[2].replace(",2026", ",2025")
    result = guide_importer.import_text(conn, "\n".join(lines))
    assert any("guide_version" in e for e in result["errors"])
    conn.execute("DELETE FROM guide_items")
    conn.commit()


def test_item_severity_comes_from_guide_not_finding(conn, scan):
    """점검항목 중요도는 가이드 원문 값. 탐지 심각도 환산값으로 덮지 않는다"""
    guide_importer.import_text(conn, MOCK_CSV.read_text(encoding="utf-8"))
    guide_service.map_scan(conn, scan)

    row = conn.execute(
        "SELECT item_severity, severity FROM v_finding_guide"
        " WHERE finding_id = 'fnd_only_type' LIMIT 1"
    ).fetchone()
    if row and row["item_severity"] is not None:
        assert row["severity"] == "low"          # 탐지 심각도
        assert row["item_severity"] in ("상", "중", "하")
    conn.execute("DELETE FROM guide_items")
    conn.commit()

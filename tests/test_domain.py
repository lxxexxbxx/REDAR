"""M1 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M1)."""
from __future__ import annotations

import csv
from datetime import datetime

import pytest

from app.config import settings
from app.domain import fingerprint as fp
from app.domain import models
from app.domain import version as ver
from app.domain.enums import (
    CompareState,
    FindingStatus,
    GuideVerdict,
    Severity,
    SeverityGuide,
    TemplateSource,
    VulnType,
)
from app.domain.models import (
    Finding,
    GuideMapping,
    Report,
    ReportMeta,
    Target,
    format_coverage_notice,
)
from app.domain.severity import convert
from app.domain.vuln_type import TypeRule, normalize
from app.repository.rules import load_vuln_type_rules

# ------------------------------------------------------------------ Enum


def _notice_tail() -> str:
    """고지 문구의 고정부. 표현이 바뀌어도 존재 여부는 계속 검증"""
    return models.COVERAGE_NOTICE_TEMPLATE.split("{scope}")[-1].strip()

def test_enum_values_match_api_spec():
    """docs/00_API_SPEC.md §0.4 와 정확히 일치"""
    assert [s.value for s in Severity] == ["critical", "high", "medium", "low", "info"]
    assert [s.value for s in SeverityGuide] == ["상", "중", "하"]
    assert [v.value for v in VulnType] == [
        "rce", "sqli", "xss", "csrf", "ssrf", "auth_bypass", "deserialization",
        "path_traversal", "file_upload", "open_redirect", "info_disclosure",
        "access_control", "misconfig", "other",
    ]
    assert len(list(VulnType)) == 14
    assert [f.value for f in FindingStatus] == [
        "open", "false_positive", "accepted_risk"
    ]
    assert [t.value for t in TemplateSource] == ["official", "custom"]
    assert [g.value for g in GuideVerdict] == ["safe", "vulnerable", "not_applicable"]
    assert [c.value for c in CompareState] == ["resolved", "persisted", "emerged"]


def test_vuln_type_rules_csv_uses_only_known_enum_values():
    """CSV 에 Enum 외 값 유입 시 적재는 성공하고 정규화에서 실패"""
    with (settings.DATA_DIR / "vuln_type_rules.csv").open(encoding="utf-8-sig") as fh:
        values = {row["vuln_type"] for row in csv.DictReader(fh)}
    assert values <= {v.value for v in VulnType}


# ------------------------------------------------------------ fingerprint

_ARGS = ("wordpress-xyz-rce", "example.com", 8080, "/wp-json/xyz/v1/run", "status")


def test_fingerprint_is_deterministic():
    assert fp.make_fingerprint(*_ARGS) == fp.make_fingerprint(*_ARGS)
    assert len(fp.make_fingerprint(*_ARGS)) == 64


def test_query_string_does_not_affect_fingerprint():
    """?page=1 이 fingerprint 를 변경하면 재스캔 비교가 전부 '신규'로 집계"""
    base = fp.make_fingerprint("t", "h", 80, "/a/b")
    assert fp.make_fingerprint("t", "h", 80, "/a/b?page=1") == base
    assert fp.make_fingerprint("t", "h", 80, "/a/b?page=2&x=y") == base
    assert fp.make_fingerprint("t", "h", 80, "/a/b#frag") == base


def test_full_url_and_path_are_equivalent():
    assert fp.make_fingerprint("t", "h", 80, "http://h:80/a/b?q=1") == \
        fp.make_fingerprint("t", "h", 80, "/a/b")


def test_trailing_slash_normalized():
    assert fp.normalize_path("/a/b/") == "/a/b"
    assert fp.normalize_path("/") == ""
    assert fp.normalize_path("http://h/") == ""


def test_path_case_is_preserved():
    """경로는 대소문자 구분"""
    assert fp.normalize_path("/Admin") == "/Admin"
    assert fp.make_fingerprint("t", "h", 80, "/Admin") != \
        fp.make_fingerprint("t", "h", 80, "/admin")


def test_distinct_inputs_differ():
    seen = {
        fp.make_fingerprint(*_ARGS),
        fp.make_fingerprint("other-template", *_ARGS[1:]),
        fp.make_fingerprint(_ARGS[0], "other.host", *_ARGS[2:]),
        fp.make_fingerprint(_ARGS[0], _ARGS[1], 443, *_ARGS[3:]),
        fp.make_fingerprint(*_ARGS[:3], "/other/path", _ARGS[4]),
        fp.make_fingerprint(*_ARGS[:4], "other-matcher"),
    }
    assert len(seen) == 6


# -------------------------------------------------------------- severity


@pytest.mark.parametrize(
    "score,severity,guide",
    [
        (9.8, Severity.CRITICAL, SeverityGuide.SANG),
        (10.0, Severity.CRITICAL, SeverityGuide.SANG),
        (9.0, Severity.CRITICAL, SeverityGuide.SANG),
        (8.9, Severity.HIGH, SeverityGuide.SANG),
        (7.0, Severity.HIGH, SeverityGuide.SANG),
        (6.9, Severity.MEDIUM, SeverityGuide.JUNG),
        (5.0, Severity.MEDIUM, SeverityGuide.JUNG),
        (4.0, Severity.MEDIUM, SeverityGuide.JUNG),
        (3.9, Severity.LOW, SeverityGuide.HA),
        (0.1, Severity.LOW, SeverityGuide.HA),
        (0.0, Severity.INFO, SeverityGuide.HA),
        (None, Severity.INFO, SeverityGuide.HA),   # 미산정
    ],
)
def test_cvss_conversion(score, severity, guide):
    assert convert(score) == (severity, guide)


# ------------------------------------------------------------- vuln_type


@pytest.fixture(scope="module")
def rules(db_path):
    """DB 에 적재된 실제 129개 규칙"""
    from app.repository.db import session

    with session(db_path) as conn:
        return load_vuln_type_rules(conn)


def test_rules_loaded(rules):
    assert len(rules) == 129


def test_unmatched_falls_back_to_other(rules):
    assert normalize(
        tags=["nonexistent-tag"], cwe_ids=["CWE-99999"],
        template_id="no-such-template", rules=rules,
    ) is VulnType.OTHER
    assert normalize(rules=rules) is VulnType.OTHER


def test_cwe_wins_over_tag(rules):
    """cwe_id(priority 10) 가 tag(50~) 보다 우선"""
    assert normalize(cwe_ids=["CWE-89"], tags=["xss"], rules=rules) is VulnType.SQLI


def test_cwe_matching_is_case_insensitive(rules):
    assert normalize(cwe_ids=["cwe-79"], rules=rules) is VulnType.XSS


@pytest.mark.parametrize(
    "cwe,expected",
    [
        ("CWE-94", VulnType.RCE),
        ("CWE-89", VulnType.SQLI),
        ("CWE-79", VulnType.XSS),
        ("CWE-352", VulnType.CSRF),           # v0.2 추가
        ("CWE-434", VulnType.FILE_UPLOAD),    # v0.2 추가
        ("CWE-601", VulnType.OPEN_REDIRECT),  # v0.2 추가
    ],
)
def test_cwe_mapping(rules, cwe, expected):
    assert normalize(cwe_ids=[cwe], rules=rules) is expected


def test_same_priority_uses_first_defined_rule():
    """동순위는 먼저 정의된 규칙 적용. sorted() 안정 정렬 의존"""
    ordered = [
        TypeRule("tag", "dup", VulnType.XSS, 50),
        TypeRule("tag", "dup", VulnType.SQLI, 50),
    ]
    assert normalize(tags=["dup"], rules=ordered) is VulnType.XSS
    assert normalize(tags=["dup"], rules=list(reversed(ordered))) is VulnType.SQLI


def test_template_prefix_is_last_resort():
    rules_ = [
        TypeRule("template_prefix", "wordpress-", VulnType.MISCONFIG, 95),
        TypeRule("cwe_id", "CWE-79", VulnType.XSS, 10),
    ]
    assert normalize(template_id="wordpress-foo", rules=rules_) is VulnType.MISCONFIG
    assert normalize(
        template_id="wordpress-foo", cwe_ids=["CWE-79"], rules=rules_
    ) is VulnType.XSS


# ---------------------------------------------------------------- version


def test_tc_v01_version_compare():
    """TC-V01. 문자열 비교는 '4.10.1' < '4.9.0' 으로 오판"""
    assert ver.compare("4.10.1", "4.9.0") == 1
    assert "4.10.1" < "4.9.0"          # 문자열 비교가 실제로 오판함을 명시
    assert ver.sort_key("4.10.1") > ver.sort_key("4.9.0")
    assert ver.max_version(["4.9.0", "4.10.1", "4.2.7.1"]) == "4.10.1"


def test_sort_key_format():
    assert ver.sort_key("4.10.1") == "00004.00010.00001"
    assert ver.sort_key("") == ""
    assert ver.sort_key(None) == ""


def test_compare_and_outdated():
    assert ver.compare("1.0.0", "1.0.0") == 0
    assert ver.compare("1.0.0", "1.0.1") == -1
    assert ver.is_outdated("4.2.6.9", "4.2.7.1") is True
    assert ver.is_outdated("4.2.7.1", "4.2.7.1") is False
    # 한쪽이라도 불명이면 판정 보류
    assert ver.is_outdated(None, "1.0") is False
    assert ver.is_outdated("1.0", None) is False


def test_sort_key_matches_bundled_advisory_keys():
    """fixed_version_key 형식 불일치 시 v_patch_plan 이 오류 없이 패치 목표만 소실.
    951행 전체 대조"""
    path = settings.DATA_DIR / "component_advisories.csv"
    with path.open(encoding="utf-8-sig") as fh:
        rows = [r for r in csv.DictReader(fh) if r["fixed_version"]]
    assert rows, "fixed_version 이 있는 행이 없다"
    mismatched = [
        (r["fixed_version"], r["fixed_version_key"], ver.sort_key(r["fixed_version"]))
        for r in rows
        if ver.sort_key(r["fixed_version"]) != r["fixed_version_key"]
    ]
    assert not mismatched, mismatched[:5]


# ----------------------------------------------------------------- models


def test_finding_model_defaults_and_strictness():
    f = Finding(
        finding_id="fnd_1", scan_id="scn_1", fingerprint="a" * 64,
        template_id="t", name="n", severity=Severity.HIGH,
        severity_guide=SeverityGuide.SANG,
        target=Target(raw="http://h/", host="h"),
        detected_at=datetime(2026, 8, 27, 12, 0, 0),
    )
    assert f.vuln_type is VulnType.OTHER
    assert f.status is FindingStatus.OPEN
    assert f.guide_refs == []          # 가이드 미탑재 상태 = 정상
    assert f.evidence.extracted_values == []

    with pytest.raises(Exception):     # extra="forbid"
        Finding(**{**f.model_dump(), "typo_field": 1})


# ------------------------------------------------------------ Report 골격

# docs/00_API_SPEC.md §1.3 최상위 키 전부. "위 최상위 키가 보고서 골격의 전부"
TOP_LEVEL_KEYS = {
    "report_id", "scan_id", "generated_at", "meta", "executive_summary",
    "environment_profile", "findings_by_severity", "findings_by_vuln_type",
    "findings_detail", "remediation", "patch_plan", "guide_mapping",
    "unmapped_findings", "false_positives", "appendix",
}


def _empty_report(scan_id: str = "scn_1") -> Report:
    return Report(
        report_id="rpt_1",
        scan_id=scan_id,
        generated_at=datetime(2026, 8, 27, 15, 0, 0),
        meta=ReportMeta(target_summary="example.com:8080", tool_version="0.3.0"),
        guide_mapping=GuideMapping(coverage_notice=format_coverage_notice(0, 36)),
    )


def test_empty_report_keeps_full_skeleton():
    """탐지 0건에도 섹션 유지 (절대규칙 4). TC-R05 의 모델 단계"""
    r = _empty_report()
    assert set(r.model_dump()) == TOP_LEVEL_KEYS
    # 심각도 5종·유형 14종 항상 전부 존재, 값은 0
    assert [g.severity for g in r.findings_by_severity] == list(Severity)
    assert [g.vuln_type for g in r.findings_by_vuln_type] == list(VulnType)
    assert len(r.findings_by_vuln_type) == 14
    assert all(g.count == 0 for g in r.findings_by_vuln_type)
    assert set(r.executive_summary.by_severity) == set(Severity)
    assert set(r.executive_summary.by_vuln_type) == set(VulnType)
    # 누락 시 Part A 와 Part B 건수 불일치
    assert r.unmapped_findings == []
    assert r.false_positives == []


def test_tc_r07_skeleton_is_target_independent():
    """대상이 달라도 골격 구조 완전 동일 (TC-R07 의 모델 단계)"""
    def shape(obj):
        if isinstance(obj, dict):
            return {k: shape(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [shape(v) for v in obj]
        return type(obj).__name__

    a = _empty_report("scn_a").model_dump()
    b = _empty_report("scn_b").model_dump()
    assert shape(a) == shape(b)


def test_coverage_notice_is_required():
    """누락 시 '점검하지 않은 것'이 '양호'로 오독. 기본값 없음"""
    with pytest.raises(Exception):
        GuideMapping()


def test_coverage_notice_text():
    notice = format_coverage_notice(382, 36)
    assert "382개 점검항목 중 36개만" in notice
    assert _notice_tail() in notice


def test_guide_mapping_defaults_to_unavailable():
    """가이드 본문 미탑재 = 정상 상태 (절대규칙 3)"""
    gm = _empty_report().guide_mapping
    assert gm.available is False
    assert gm.items == []

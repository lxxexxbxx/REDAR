"""M9 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M9).

LLM 없이 보고서가 완성품이어야 한다. 이 파일은 '없어도 된다' 를 증명함
"""
from __future__ import annotations

import json

import pytest

from app.adapters.llm import get_provider
from app.adapters.llm.base import (
    MAX_CALLS_PER_REPORT,
    MAX_REMEDIATION_CALLS,
    TEMPERATURE,
    LlmError,
)
from app.adapters.llm.masking import Masker
from app.adapters.llm.null import NullProvider
from app.report import builder, renderer
from app.repository import reports as report_repo
from app.repository import settings_repo
from app.services import guide_importer, narrative_service, report_service
from tests.test_report import MOCK_CSV, _make_scan


class FakeProvider:
    """호출 기록을 남기는 Provider. 실제 통신하지 않음"""

    name = "monogpt"
    model = "fake-1"

    def __init__(self, fail_on: set[str] | None = None) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.fail_on = fail_on or set()

    def narrate(self, purpose: str, context: dict) -> str:
        self.calls.append((purpose, context))
        if purpose in self.fail_on:
            raise LlmError("의도적 실패")
        return f"[{purpose}] 생성된 문장 · TARGET_1 참고"


@pytest.fixture
def llm_on(conn):
    settings_repo.put_many(conn, {
        "llm_enabled": True, "offline_mode": False,
        "ext_llm_api_enabled": True, "llm_provider": "monogpt",
        "llm_endpoint": "http://llm.invalid/v1/chat",
        "llm_mask_identifiers": True,
    })
    yield
    settings_repo.put_many(conn, {
        "llm_enabled": False, "offline_mode": True,
        "ext_llm_api_enabled": False, "llm_provider": "null", "llm_endpoint": "",
    })


@pytest.fixture
def scan(conn):
    guide_importer.import_text(conn, MOCK_CSV.read_text(encoding="utf-8"))
    scan_id = _make_scan(conn, "scn_llm", "wp.local", [
        {"finding_id": "fnd_l1", "name": "XSS 취약점", "severity": "critical",
         "vuln_type": "xss", "cwe_ids": ["CWE-79"], "cvss_score": 9.1},
        {"finding_id": "fnd_l2", "name": "SQL 인젝션", "severity": "high",
         "vuln_type": "sqli", "cwe_ids": ["CWE-89"]},
    ])
    yield scan_id
    conn.execute("DELETE FROM findings WHERE scan_id = 'scn_llm'")
    conn.execute("DELETE FROM scans WHERE scan_id = 'scn_llm'")
    conn.execute("DELETE FROM guide_items")
    conn.commit()


def _report(conn, scan_id, **options):
    return builder.build(conn, scan_id, report_id="rpt_llm", **options)


# ─────────────────────────────── 비활성 상태 (완료 조건 1)

def test_report_completes_without_llm(conn, scan):
    view = report_service.create(conn, scan, {"use_llm": False})
    report = view["report"]
    assert view["status"] == "completed"
    assert report["executive_summary"]["narrative_generated_by"] == "template"
    assert report["executive_summary"]["narrative"]
    assert report["appendix"]["llm_generated_sections"] == []
    assert bool(view["llm_used"]) is False


def test_null_provider_returns_empty(conn):
    provider = NullProvider()
    assert provider.narrate("executive_summary", {"x": 1}) == ""
    assert provider.name == "null"


def test_default_provider_is_null():
    """기본 Provider 는 NullProvider 다 (절대규칙 2)"""
    assert get_provider(None).name == "null"
    assert get_provider("").name == "null"
    assert get_provider("존재하지-않는-provider").name == "null"


def test_temperature_is_zero():
    assert TEMPERATURE == 0


# ─────────────────────────────── 예외 미전파 (완료 조건 2)

def test_exception_does_not_propagate_and_counts_fallback(conn, scan, llm_on,
                                                          monkeypatch):
    provider = FakeProvider(fail_on={"executive_summary"})
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: provider
    )
    report = narrative_service.apply(conn, _report(conn, scan))

    # 예외가 올라오지 않고 템플릿 문장이 남음
    assert report["executive_summary"]["narrative_generated_by"] == "template"
    assert report["meta"]["llm"]["fallback_count"] >= 1


def test_total_failure_keeps_report_usable(conn, scan, llm_on, monkeypatch):
    provider = FakeProvider(fail_on={
        "executive_summary", "remediation_rewrite", "vuln_description",
    })
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: provider
    )
    report = narrative_service.apply(conn, _report(conn, scan))
    assert report["appendix"]["llm_generated_sections"] == []
    assert report["meta"]["llm"]["used"] is False
    html = renderer.render_html(report)
    assert "A-1. 개요 및 집계" in html


def test_fallback_count_recorded_on_report_row(conn, scan, llm_on, monkeypatch):
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider",
        lambda *a, **k: FakeProvider(fail_on={"executive_summary"}),
    )
    view = report_service.create(conn, scan, {"use_llm": True})
    row = conn.execute(
        "SELECT llm_fallback_count, llm_used, llm_provider FROM reports"
        " WHERE report_id = ?", (view["report_id"],)
    ).fetchone()
    assert row["llm_fallback_count"] >= 1


# ─────────────────────────────── 호출 횟수 (완료 조건 5)

def test_call_count_within_limit(conn, scan, llm_on, monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: provider
    )
    report = narrative_service.apply(conn, _report(conn, scan))
    assert len(provider.calls) <= MAX_CALLS_PER_REPORT
    assert report["meta"]["llm"]["calls"] == len(provider.calls)


def test_description_cached_per_template(conn, scan, llm_on, monkeypatch):
    """같은 template_id 가 여러 호스트에서 나와도 호출은 1회"""
    conn.execute(
        "UPDATE findings SET template_id = 'same-tpl' WHERE scan_id = 'scn_llm'"
    )
    conn.commit()
    provider = FakeProvider()
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: provider
    )
    narrative_service.apply(conn, _report(conn, scan))
    description_calls = [c for c in provider.calls if c[0] == "vuln_description"]
    assert len(description_calls) == 1


def test_remediation_calls_capped(conn, scan, llm_on, monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: provider
    )
    narrative_service.apply(conn, _report(conn, scan))
    rewrite_calls = [c for c in provider.calls if c[0] == "remediation_rewrite"]
    assert len(rewrite_calls) <= MAX_REMEDIATION_CALLS


def test_purpose_whitelist_enforced(conn, scan, llm_on):
    with pytest.raises(ValueError, match="허용되지 않은 purpose"):
        narrative_service._call(FakeProvider(), None, "make_verdict", {})


# ─────────────────────────────── 오프라인 차단 (완료 조건 6)

def test_offline_mode_blocks_llm(conn, scan, llm_on, monkeypatch):
    settings_repo.put_many(conn, {"offline_mode": True})
    provider = FakeProvider()
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: provider
    )
    report = narrative_service.apply(conn, _report(conn, scan))
    assert provider.calls == []
    assert "오프라인" in report["meta"]["llm"]["blocked_reason"]


def test_endpoint_disabled_blocks_llm(conn, scan, llm_on, monkeypatch):
    settings_repo.put_many(conn, {"ext_llm_api_enabled": False})
    provider = FakeProvider()
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: provider
    )
    report = narrative_service.apply(conn, _report(conn, scan))
    assert provider.calls == []
    assert report["meta"]["llm"]["used"] is False


def test_llm_disabled_blocks_llm(conn, scan, llm_on, monkeypatch):
    settings_repo.put_many(conn, {"llm_enabled": False})
    provider = FakeProvider()
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: provider
    )
    narrative_service.apply(conn, _report(conn, scan))
    assert provider.calls == []


# ─────────────────────────────── 마스킹 (완료 조건 4)

@pytest.mark.parametrize("text", [
    "http://wp.local:8080/wp-admin/ 에서 확인",
    "192.168.1.50 대상 점검",
    "internal.corp.example.com 의 /wp-content/uploads/ 경로",
])
def test_mask_then_unmask_round_trip(text):
    masker = Masker()
    masked = masker.mask(text)
    assert masked != text
    assert masker.unmask(masked) == text


def test_mask_hides_host_and_path():
    masker = Masker()
    masked = masker.mask("http://internal.corp.local/wp-config.php.bak")
    assert "internal" not in masked
    assert "wp-config" not in masked
    assert "TARGET_1" in masked


def test_unmask_handles_double_digit_tokens():
    """TARGET_1 이 TARGET_10 을 깨뜨리지 않아야 한다"""
    masker = Masker()
    hosts = [f"host{i}.local" for i in range(1, 13)]
    masked = masker.mask(" ".join(hosts))
    assert masker.unmask(masked) == " ".join(hosts)


def test_mask_context_recurses():
    masker = Masker()
    masked = masker.mask_context({
        "target": "http://wp.local/x",
        "list": ["10.0.0.1"],
        "nested": {"path": "/wp-admin/"},
        "number": 42,
    })
    assert masked["number"] == 42
    assert "wp.local" not in json.dumps(masked, ensure_ascii=False)
    assert "10.0.0.1" not in json.dumps(masked, ensure_ascii=False)


def test_llm_response_is_unmasked(conn, scan, llm_on, monkeypatch):
    """전송 시 치환된 식별자가 응답에서 원래 값으로 되돌아와야 한다"""

    class EchoProvider:
        name = "monogpt"
        model = "echo"

        def narrate(self, purpose, context):
            # 마스킹된 값을 그대로 되돌려주는 Provider
            return f"대상 {context.get('name', '')} 점검 필요"

    conn.execute(
        "UPDATE findings SET name = 'http://wp.local/wp-admin/ 노출'"
        " WHERE finding_id = 'fnd_l1'"
    )
    conn.commit()
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: EchoProvider()
    )
    report = narrative_service.apply(conn, _report(conn, scan))

    expanded = [
        b.get("description_expanded") for b in report["findings_detail"]
        if b.get("description_expanded")
    ]
    assert expanded, "설명 확장이 있어야 한다"
    joined = " ".join(expanded)
    # 발급한 토큰은 역치환됨. 발급하지 않은 토큰은 그대로 남는 것이 정상
    assert "TARGET_" not in joined
    assert "wp.local" in joined


# ─────────────────────────────── preview (완료 조건 3)

def test_preview_excludes_response_body(conn, scan):
    report = _report(conn, scan)
    conn.execute(
        "UPDATE findings SET ev_response = 'SECRET-RESPONSE-BODY'"
        " WHERE scan_id = 'scn_llm'"
    )
    conn.commit()
    report = _report(conn, scan)
    result = narrative_service.preview(conn, report)

    serialized = json.dumps(result, ensure_ascii=False)
    assert "SECRET-RESPONSE-BODY" not in serialized
    assert "요청·응답 원문" in result["excluded"]


def test_preview_masks_identifiers(conn, scan):
    result = narrative_service.preview(conn, _report(conn, scan))
    assert result["masked"] is True
    serialized = json.dumps(result["payloads"], ensure_ascii=False)
    assert "wp.local" not in serialized


def test_preview_reports_estimated_calls(conn, scan):
    result = narrative_service.preview(conn, _report(conn, scan))
    assert 1 <= result["estimated_calls"] <= MAX_CALLS_PER_REPORT


# ─────────────────────────────── 원문 병기 (완료 조건 7)

def test_remediation_keeps_original_alongside_llm_text(conn, scan, llm_on,
                                                       monkeypatch):
    """LLM 이 다듬은 문장과 가이드 원문이 함께 남아야 한다 (절대규칙 9)"""
    provider = FakeProvider()
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: provider
    )
    report = narrative_service.apply(conn, _report(conn, scan))

    rewritten = [i for i in report["remediation"] if i.get("narrative")]
    assert rewritten, "재서술된 항목이 있어야 한다"
    for item in rewritten:
        assert item["guide_remediation_original"]
        assert item["narrative"] != item["guide_remediation_original"]

    html = renderer.render_html(report)
    assert rewritten[0]["guide_remediation_original"] in html


def test_llm_does_not_invent_remediation_when_no_original(conn, scan, llm_on,
                                                          monkeypatch):
    """원문이 없는 항목은 LLM 에 넘기지 않음. 가짜 조치 방법 생성 방지"""
    conn.execute("UPDATE guide_items SET remediation = NULL")
    conn.commit()
    provider = FakeProvider()
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: provider
    )
    narrative_service.apply(conn, _report(conn, scan))
    assert [c for c in provider.calls if c[0] == "remediation_rewrite"] == []


# ─────────────────────────────── 정렬 불변 (완료 조건 8)

def test_llm_does_not_change_section_order(conn, scan, llm_on, monkeypatch):
    """LLM on/off 로 v_report_sections 정렬 순서가 바뀌지 않아야 한다"""
    without = [i["item_code"] for i in _report(conn, scan)["remediation"]]

    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: FakeProvider()
    )
    with_llm = narrative_service.apply(conn, _report(conn, scan))
    assert [i["item_code"] for i in with_llm["remediation"]] == without

    scores = [i["priority_score"] for i in with_llm["remediation"]]
    assert scores == sorted(scores, reverse=True)


def test_llm_does_not_change_toc(conn, scan, llm_on, monkeypatch):
    from tests.test_report import EXPECTED_SECTIONS, _sections

    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: FakeProvider()
    )
    report = narrative_service.apply(conn, _report(conn, scan))
    assert _sections(renderer.render_html(report)) == EXPECTED_SECTIONS


def test_llm_does_not_change_verdicts(conn, scan, llm_on, monkeypatch):
    """판정은 LLM 이 건드리지 않음 (절대규칙 2)"""
    before = _report(conn, scan)["guide_mapping"]["summary"]
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: FakeProvider()
    )
    after = narrative_service.apply(conn, _report(conn, scan))
    assert after["guide_mapping"]["summary"] == before


def test_generated_sections_recorded(conn, scan, llm_on, monkeypatch):
    monkeypatch.setattr(
        "app.services.narrative_service.get_provider", lambda *a, **k: FakeProvider()
    )
    report = narrative_service.apply(conn, _report(conn, scan))
    assert "executive_summary.narrative" in report["appendix"]["llm_generated_sections"]

    html = renderer.render_html(report)
    assert "[AI 생성 — 적용 전 검토 필요]" in html

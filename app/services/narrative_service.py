"""LLM 서술 레이어 (docs/04 §5).

완결된 Report JSON 의 산문 필드만 덮음. 판정·구조·정렬에 개입하지 않음
실패는 예외로 올리지 않고 템플릿 문장을 남김 (절대규칙 2)

전송 데이터는 화이트리스트로 생성. 응답 본문·추출값·자격증명은 컨텍스트에
넣지 않으며, 호스트·경로는 마스킹 후 전송 (docs/01 §7.4)
"""
from __future__ import annotations

import logging
import sqlite3
from typing import Any

from app.adapters.llm import get_provider
from app.adapters.llm.base import (
    MAX_CALLS_PER_REPORT,
    MAX_REMEDIATION_CALLS,
    PURPOSES,
)
from app.adapters.llm.masking import Masker
from app.report import fallback
from app.repository import settings_repo

logger = logging.getLogger(__name__)

GENERATED_BY_LLM = "llm"


class Budget:
    """호출 횟수 상한. finding 마다 호출하면 수백 회가 된다"""

    def __init__(self, limit: int = MAX_CALLS_PER_REPORT) -> None:
        self.limit = limit
        self.used = 0

    def take(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


def apply(conn: sqlite3.Connection, report: dict[str, Any]) -> dict[str, Any]:
    """Report JSON 의 산문 필드를 LLM 문장으로 교체. 실패 시 원상 유지"""
    raw = settings_repo.get_all(conn)
    enabled = settings_repo.as_bool(raw.get("llm_enabled"))
    offline = settings_repo.offline_mode(conn)
    endpoint_on = settings_repo.as_bool(raw.get("ext_llm_api_enabled"))

    blocked_reason = None
    if not enabled:
        blocked_reason = "LLM 설정 꺼짐"
    elif offline:
        # 오프라인 모드는 개별 설정과 무관하게 전부 차단 (절대규칙 5)
        blocked_reason = "오프라인 모드. LLM 호출 안 함"
    elif not endpoint_on:
        blocked_reason = "LLM 통신 지점이 비활성 상태입니다."

    if blocked_reason:
        report["meta"]["llm"] = {
            **report["meta"]["llm"],
            "used": False, "provider": "null", "blocked_reason": blocked_reason,
            "fallback_count": 0, "calls": 0,
        }
        return report

    provider = get_provider(raw.get("llm_provider"), {
        "endpoint": raw.get("llm_endpoint"),
        "api_key": raw.get("llm_api_key"),
        "model": raw.get("llm_model"),
    })
    masker = Masker() if settings_repo.as_bool(
        raw.get("llm_mask_identifiers"), default=True
    ) else None

    budget = Budget()
    state = {"fallbacks": 0, "sections": []}

    _narrate_summary(provider, masker, budget, state, report)
    _narrate_remediation(provider, masker, budget, state, report)
    _narrate_descriptions(provider, masker, budget, state, report)

    report["appendix"]["llm_generated_sections"] = state["sections"]
    report["meta"]["llm"] = {
        **report["meta"]["llm"],
        "used": bool(state["sections"]),
        "provider": provider.name,
        "model": provider.model,
        "prompt_version": "p1",
        "fallback_count": state["fallbacks"],
        "calls": budget.used,
        "masked": masker is not None,
    }
    return report


def _call(
    provider, masker: Masker | None, purpose: str, context: dict[str, Any]
) -> str | None:
    """1회 호출. 예외를 상위로 올리지 않음 (구현 규칙 1)"""
    if purpose not in PURPOSES:
        raise ValueError(f"허용되지 않은 purpose: {purpose}")
    payload = masker.mask_context(context) if masker else context
    try:
        text = provider.narrate(purpose, payload)
    except Exception:  # noqa: BLE001 - 보고서 생성이 API 가용성에 의존할 수 없다
        logger.warning("LLM fallback: %s", purpose, exc_info=True)
        return None
    if not text:
        return None
    return masker.unmask(text) if masker else text


def _narrate_summary(provider, masker, budget, state, report) -> None:
    if not budget.take():
        return
    summary = report["executive_summary"]
    text = _call(provider, masker, "executive_summary", {
        # 화이트리스트. 집계 수치와 상위 위험 이름만 전송
        "total_findings": summary["total_findings"],
        "by_severity": summary["by_severity"],
        "by_vuln_type": summary["by_vuln_type"],
        "top_risks": [
            {"name": r["name"], "severity": r["severity"]}
            for r in summary["top_risks"]
        ],
    })
    if text is None:
        state["fallbacks"] += 1
        return
    summary["narrative"] = text
    summary["narrative_generated_by"] = GENERATED_BY_LLM
    state["sections"].append("executive_summary.narrative")


def _narrate_remediation(provider, masker, budget, state, report) -> None:
    """상위 priority_score 항목만. 정렬은 SQL 이 이미 확정함"""
    targets = [
        item for item in report["remediation"]
        if item.get("guide_remediation_original")
    ][:MAX_REMEDIATION_CALLS]

    for index, item in enumerate(targets):
        if not budget.take():
            return
        text = _call(provider, masker, "remediation_rewrite", {
            "item_code": item["item_code"],
            "title": item["title"],
            # 원문을 넘기고 다듬게 한다. 새 조치를 만들게 하지 않음
            "guide_remediation_original": item["guide_remediation_original"],
            "finding_count": len(item["finding_ids"]),
        })
        if text is None:
            state["fallbacks"] += 1
            continue
        # 원문 병기 필수. guide_remediation_original 은 그대로 유지됨 (절대규칙 9)
        item["narrative"] = text
        item["narrative_generated_by"] = GENERATED_BY_LLM
        state["sections"].append(f"remediation[{index}].narrative")


def _narrate_descriptions(provider, masker, budget, state, report) -> None:
    """template_id 단위 캐시. 같은 취약점이 50대에서 나와도 호출은 1회"""
    cache: dict[str, str] = {}
    for block in report["findings_detail"]:
        template_id = block["template_id"]
        if template_id in cache:
            block["description_expanded"] = cache[template_id]
            continue
        if not budget.take():
            return
        text = _call(provider, masker, "vuln_description", {
            "template_id": template_id,
            "name": block["name"],
            "severity": block["severity"],
            "cve_ids": block["cve_ids"],
            "cwe_ids": block["cwe_ids"],
            "cvss_score": block["cvss_score"],
            "description": block.get("description"),
        })
        if text is None:
            state["fallbacks"] += 1
            continue
        cache[template_id] = text
        block["description_expanded"] = text
        state["sections"].append(f"findings_detail[{template_id}].description")


def preview(conn: sqlite3.Connection, report: dict[str, Any]) -> dict[str, Any]:
    """전송 데이터 미리보기 (docs/00 §7). 응답 본문은 포함되지 않음"""
    raw = settings_repo.get_all(conn)
    masker = Masker() if settings_repo.as_bool(
        raw.get("llm_mask_identifiers"), default=True
    ) else None

    summary = report["executive_summary"]
    payloads = {
        "executive_summary": {
            "total_findings": summary["total_findings"],
            "by_severity": summary["by_severity"],
            "top_risks": [
                {"name": r["name"], "severity": r["severity"]}
                for r in summary["top_risks"]
            ],
        },
    }
    remediation = [
        item for item in report["remediation"]
        if item.get("guide_remediation_original")
    ][:MAX_REMEDIATION_CALLS]
    if remediation:
        payloads["remediation_rewrite"] = {
            "item_code": remediation[0]["item_code"],
            "guide_remediation_original":
                remediation[0]["guide_remediation_original"],
        }

    masked = {
        purpose: (masker.mask_context(payload) if masker else payload)
        for purpose, payload in payloads.items()
    }
    return {
        "masked": masker is not None,
        "mask_map_size": len(masker.mapping) if masker else 0,
        "payloads": masked,
        "excluded": [
            "요청·응답 원문", "추출값", "내부 경로", "자격증명",
        ],
        "estimated_calls": min(
            MAX_CALLS_PER_REPORT,
            1 + len(remediation) + len({
                b["template_id"] for b in report["findings_detail"]
            }),
        ),
    }


def fallback_narrative(total: int, by_severity: dict[str, int]) -> str:
    return fallback.executive_summary(total, by_severity)

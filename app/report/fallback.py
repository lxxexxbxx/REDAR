"""LLM 없이 쓰는 사전 정의 문장 (docs/04 §5.4).

Fallback 문장만으로도 보고서가 성립해야 한다. LLM 은 품질 향상 수단이지
필수 구성요소가 아님 (절대규칙 2). 기본 Provider 가 NullProvider 인 이유
"""
from __future__ import annotations

from typing import Any

from app.domain.enums import Severity

GENERATED_BY_TEMPLATE = "template"

# 판정·구조·조치방법 생성에 개입하지 않음. 산문 필드만 채움 (절대규칙 2)
_NO_FINDING = (
    "본 진단에서 탐지된 취약점이 없습니다. "
    "다만 웹 요청으로 확인할 수 없는 항목이 있습니다."
)


def executive_summary(total: int, by_severity: dict[str, int]) -> str:
    if total == 0:
        return _NO_FINDING
    parts = ", ".join(
        f"{severity.value} {by_severity.get(severity.value, 0)}건"
        for severity in Severity
    )
    return (
        f"본 진단에서 총 {total}건의 취약점이 탐지되었습니다. "
        f"심각도별로는 {parts}입니다. "
        "조치 우선순위는 critical·high 등급 항목부터 적용할 것을 권고합니다."
    )


def top_risk_reason(finding: dict[str, Any]) -> str:
    severity = finding["severity"]
    cves = finding.get("cve_ids") or []
    suffix = f" · {', '.join(cves[:2])}" if cves else ""
    return f"{severity} 등급{suffix}"


def remediation_summary(item: dict[str, Any]) -> str:
    """가이드 원문이 없을 때만 쓰는 대체 문구.

    원문이 있으면 그대로 인용. 다듬은 문장으로 대체 금지 (절대규칙 9)
    """
    return (
        f"{item.get('name') or '해당 항목'}에 대한 조치는 "
        "템플릿 메타데이터의 권고 사항 또는 제품 벤더 공지를 확인하여 적용하십시오."
    )


def temporary_fix() -> str:
    return "조치 적용 전까지 해당 경로에 대한 외부 접근을 차단하십시오."


NOT_APPLICABLE = "해당 없음"
GUIDE_UNAVAILABLE = (
    "가이드 본문이 탑재되지 않아 점검항목 상세를 표시할 수 없습니다. "
    "매핑 결과는 보존되어 있으며 본문을 임포트하면 이 파트가 채워집니다."
)
# 패치 목표 버전이 없는 항목. 빈칸은 검토자에게 데이터 누락으로 읽힘 (docs/04 A-6)
NO_UPGRADE_TARGET = "(버전 업그레이드 대상 아님 - 설정 조치 필요)"

"""nuclei tags / CWE -> VulnType 정규화.

규칙 원본은 data/vuln_type_rules.csv -> DB(vuln_type_rules).
순수 함수. DB 직접 조회 없음 (SQL 은 repository 전용). 규칙은 호출자가 주입
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.domain.enums import VulnType

MATCH_CWE = "cwe_id"
MATCH_TAG = "tag"
MATCH_TEMPLATE_PREFIX = "template_prefix"


@dataclass(frozen=True, slots=True)
class TypeRule:
    match_type: str
    match_value: str
    vuln_type: VulnType
    priority: int  # 낮을수록 우선. cwe_id 10 / tag 50~90 / template_prefix 95


def normalize(
    *,
    tags: Iterable[str] | None = None,
    cwe_ids: Iterable[str] | None = None,
    template_id: str | None = None,
    rules: Sequence[TypeRule],
) -> VulnType:
    """우선순위 순 첫 매칭 반환. 미매칭은 OTHER.

    동순위 복수 매칭 시 '먼저 정의된 규칙' 적용.
    sorted() 안정 정렬이므로 rules 가 정의 순서면 그 순서가 타이브레이커
    """
    tag_set = {t.lower() for t in (tags or ())}
    cwe_set = {c.upper() for c in (cwe_ids or ())}

    for rule in sorted(rules, key=lambda r: r.priority):
        if rule.match_type == MATCH_CWE:
            if rule.match_value.upper() in cwe_set:
                return rule.vuln_type
        elif rule.match_type == MATCH_TAG:
            if rule.match_value.lower() in tag_set:
                return rule.vuln_type
        elif rule.match_type == MATCH_TEMPLATE_PREFIX:
            if template_id and template_id.startswith(rule.match_value):
                return rule.vuln_type
    return VulnType.OTHER

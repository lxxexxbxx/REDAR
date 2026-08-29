"""LLMProvider 프로토콜 (docs/01 §4.2).

LLM 은 파이프라인 끝단의 산문 필드만 채움. 판정·구조 결정·조치방법 생성에
개입하지 않음 (절대규칙 2)
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

# 호출 지점 3개. 이 목록 밖의 purpose 는 거부 (docs/04 §5.2)
PURPOSES = ("executive_summary", "remediation_rewrite", "vuln_description")

# 보고서 1건당 총 호출 상한. finding 마다 호출하면 수백 회가 됨
MAX_CALLS_PER_REPORT = 10
MAX_REMEDIATION_CALLS = 5

# 온도 고정. 같은 입력에 같은 문장이 나와야 재현성 기록이 의미를 가짐
TEMPERATURE = 0


class LlmError(RuntimeError):
    """Provider 내부 실패. 호출자가 fallback 으로 전환"""


@runtime_checkable
class LLMProvider(Protocol):
    name: str
    model: str | None

    def narrate(self, purpose: str, context: dict[str, Any]) -> str:
        """정해진 필드의 텍스트만 반환. 구조를 만들지 않음"""

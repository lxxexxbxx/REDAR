"""LLMProvider 프로토콜 (docs/01 §4.2).

LLM 은 조치 가이드 전용이다. 보고서에는 개입하지 않음 (절대규칙 2)
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


class LlmError(RuntimeError):
    """Provider 내부 실패. 호출자가 fallback 으로 전환"""


@runtime_checkable
class LLMProvider(Protocol):
    name: str
    model: str | None

    def complete(
        self, messages: list[dict[str, str]], *, max_tokens: int = 4096
    ) -> str:
        """대화 1턴의 본문. 보고서에는 쓰지 않음 (절대규칙 2)"""

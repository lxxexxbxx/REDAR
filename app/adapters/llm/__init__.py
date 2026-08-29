"""LLM Provider. 기본값은 NullProvider(템플릿 문장)다 (절대규칙 2)."""
from app.adapters.llm.base import LLMProvider, LlmError, PURPOSES
from app.adapters.llm.null import NullProvider

__all__ = ["LLMProvider", "LlmError", "NullProvider", "PURPOSES", "get_provider"]


def get_provider(name: str | None, config: dict | None = None):
    """이름 -> Provider. 알 수 없으면 NullProvider.

    조용히 Null 로 떨어뜨리는 이유: LLM 은 품질 향상 수단이고 없어도 보고서가
    성립해야 한다. 여기서 예외를 올리면 설정 오타가 보고서 생성을 막음
    """
    if name in (None, "", "null", "none"):
        return NullProvider()
    if name == "monogpt":
        from app.adapters.llm.monogpt import MonoGptProvider

        return MonoGptProvider(**(config or {}))
    return NullProvider()

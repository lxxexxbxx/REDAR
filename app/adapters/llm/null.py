"""기본 Provider. 외부 통신 없이 사전 정의 문장을 돌려줌 (절대규칙 2).

이 Provider 로도 보고서가 완성품이어야 한다. LLM 은 품질 향상 수단임
"""
from __future__ import annotations


class NullProvider:
    name = "null"
    model = None

    def complete(
        self, messages: list[dict[str, str]], *, max_tokens: int = 4096
    ) -> str:
        """빈 문자열 = '생성하지 않음'. 호출자가 템플릿 문장을 유지"""
        del messages, max_tokens
        return ""

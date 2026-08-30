"""외부 LLM API Provider. 사용자가 명시적으로 활성화해야 동작 (절대규칙 5).

허용된 외부 통신 3곳 중 하나. 오프라인 모드에서는 호출 지점에서 차단됨
(narrative_service). 이 클래스는 통신만 담당하며 차단 판단을 하지 않음
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from app.adapters.llm.base import TEMPERATURE, LlmError

_TIMEOUT_SEC = 30
_MAX_RESPONSE_BYTES = 64 * 1024

# 목적별 지시문. LLM 이 구조를 만들지 않도록 '문장만' 을 명시함
_INSTRUCTION = {
    "executive_summary":
        "아래 진단 집계를 바탕으로 종합 의견을 3~5문장으로 작성하라."
        " 새로운 수치를 만들지 말고 주어진 값만 사용하라.",
    "remediation_rewrite":
        "아래 조치 방법 원문을 대상 환경에 맞게 다듬어라."
        " 원문에 없는 조치를 추가하지 마라. 3~5문장.",
    "vuln_description":
        "아래 취약점 메타데이터를 한국어 설명 2~3문장으로 확장하라."
        " 심각도나 점수를 새로 판단하지 마라.",
}


class MonoGptProvider:
    name = "monogpt"

    def __init__(
        self,
        endpoint: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model

    def narrate(self, purpose: str, context: dict[str, Any]) -> str:
        if not self.endpoint:
            raise LlmError("LLM 엔드포인트 미설정")
        payload = {
            "model": self.model,
            "temperature": TEMPERATURE,
            "messages": [
                {"role": "system", "content": _INSTRUCTION.get(purpose, "")},
                {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
            ],
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT_SEC) as response:
                body = json.loads(response.read(_MAX_RESPONSE_BYTES))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            # 자격증명이 메시지에 섞이지 않도록 예외 타입만 남김
            raise LlmError(f"LLM 호출 실패: {type(exc).__name__}") from exc

        try:
            return str(body["choices"][0]["message"]["content"]).strip()
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmError("LLM 응답 형식이 예상과 다릅니다.") from exc

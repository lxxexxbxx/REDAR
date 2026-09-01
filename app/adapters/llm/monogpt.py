"""외부 LLM API Provider. 사용자가 명시적으로 활성화해야 동작 (절대규칙 5).

허용된 외부 통신 4곳 중 하나. 오프라인 모드에서는 호출 지점에서 차단됨
(remediation_service). 이 클래스는 통신만 담당하며 차단 판단을 하지 않음
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

    def _chat_url(self) -> str:
        """base URL 을 받아 chat 경로를 붙임.

        설정에는 MonoGPT base(`.../monorouter/v1`)를 넣게 안내하지만,
        사용자가 전체 경로를 넣어도 동작해야 함
        """
        base = (self.endpoint or "").rstrip("/")
        if not base:
            raise LlmError("LLM 엔드포인트 미설정")
        return base if base.endswith("/chat/completions") else f"{base}/chat/completions"

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 4096,
    ) -> str:
        """대화 1턴. 조치 가이드는 산문이 길어 토큰 상한을 별도로 받음

        temperature 를 보내지 않는다. 최신 모델 일부가 이 값을 거부해 400 이 되고,
        MonoGPT 샘플 코드도 넣지 않는다. 프롬프트가 이미 로컬 고정 양식이라
        재현성은 그쪽에서 확보됨 (remediation_service.render_prompt)
        """
        return self._post({
            "model": self.model,
            "messages": messages,
            "max_completion_tokens": max_tokens,
        })

    def narrate(self, purpose: str, context: dict[str, Any]) -> str:
        return self._post({
            "model": self.model,
            "temperature": TEMPERATURE,
            "messages": [
                {"role": "system", "content": _INSTRUCTION.get(purpose, "")},
                {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
            ],
        })

    def _post(self, payload: dict[str, Any]) -> str:
        request = urllib.request.Request(
            self._chat_url(),
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
        except urllib.error.HTTPError as exc:
            # 상태 코드와 서버가 준 사유를 남긴다. 'HTTPError' 만 보이면
            # 키·모델 이름·크레딧 중 무엇이 문제인지 알 수 없음
            # 응답 본문에는 우리 자격증명이 들어가지 않음 (요청 헤더는 남기지 않음)
            raise LlmError(
                f"LLM 호출 실패 HTTP {exc.code}: {_reason(exc)}"
            ) from exc
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            raise LlmError(f"LLM 호출 실패: {type(exc).__name__}") from exc

        try:
            return str(body["choices"][0]["message"]["content"]).strip()
        except (KeyError, IndexError, TypeError) as exc:
            raise LlmError(f"LLM 응답 형식 예상과 다름: {str(body)[:200]}") from exc


def _reason(exc: urllib.error.HTTPError) -> str:
    """서버가 준 오류 사유. JSON 이면 message 만, 아니면 앞부분만"""
    try:
        raw = exc.read(_MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - 본문을 못 읽어도 상태 코드는 살림
        return exc.reason or "사유 없음"
    try:
        data = json.loads(raw)
    except ValueError:
        return raw.strip()[:300] or (exc.reason or "사유 없음")
    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict):
        return str(error.get("message") or error)[:300]
    return str(error or data)[:300]

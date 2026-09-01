"""외부 LLM API Provider. 사용자가 명시적으로 활성화해야 동작 (절대규칙 5).

허용된 외부 통신 4곳 중 하나. 오프라인 모드에서는 호출 지점에서 차단됨
(remediation_service). 이 클래스는 통신만 담당하며 차단 판단을 하지 않음
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from app import __version__
from app.adapters.llm.base import LlmError

# 스트리밍이라 이 값은 '다음 조각이 오기까지' 가 아니라 전체 연결 상한
_TIMEOUT_SEC = 600
# Cloudflare 가 'Python-urllib/x.y' 를 서명 기반으로 차단한다 (403 error code: 1010).
# 브라우저를 위장하지 않고 제품명을 밝힌다. 이것만으로 통과함 (실측)
_USER_AGENT = f"REDAR/{__version__}"
_MAX_RESPONSE_BYTES = 64 * 1024


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
            raise LlmError("LLM 엔드포인트가 설정되지 않았습니다.")
        return base if base.endswith("/chat/completions") else f"{base}/chat/completions"

    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 4096,
    ) -> str:
        """대화 1턴. **반드시 스트리밍으로 받는다.**

        엔드포인트 앞단이 Cloudflare 다. 비스트리밍으로 긴 응답을 요청하면 오리진이
        100초 안에 첫 바이트를 못 내보내 524 로 끊긴다 (실측: 조치 가이드 20,000토큰
        요청이 524). 스트리밍은 첫 조각이 1~2초에 나와 연결이 유지됨

        temperature 를 보내지 않는다. 최신 모델 일부가 이 값을 거부해 400 이 되고,
        MonoGPT 샘플 코드도 넣지 않는다. 프롬프트가 이미 로컬 고정 양식이라
        재현성은 그쪽에서 확보됨 (remediation_service.render_prompt)
        """
        text, finish = self._stream({
            "model": self.model,
            "messages": messages,
            "max_completion_tokens": max_tokens,
            "stream": True,
        })
        if text:
            return text
        # 추론 모델은 max_completion_tokens 를 추론 토큰과 함께 쓴다. 추론이 예산을
        # 다 먹으면 본문이 0자로 끝난다 (실측: gpt-5.5 가 6,000 전부를 추론에 사용).
        # 빈 문자열을 그대로 돌려주면 화면에 빈 말풍선만 뜬다
        if finish == "length":
            raise LlmError(
                f"모델이 출력 한도({max_tokens} 토큰)를 추론에 모두 사용해"
                " 본문이 비었습니다. 설정에서 추론을 적게 쓰는 모델로 바꾸십시오."
            )
        raise LlmError(f"LLM 이 빈 응답을 보냈습니다 (종료 사유: {finish or '없음'}).")

    def _request(self, payload: dict[str, Any], accept: str) -> urllib.request.Request:
        return urllib.request.Request(
            self._chat_url(),
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": accept,
                "User-Agent": _USER_AGENT,
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
            method="POST",
        )

    def _stream(self, payload: dict[str, Any]) -> tuple[str, str | None]:
        """SSE 조각을 이어붙여 (본문, 종료 사유) 반환"""
        request = self._request(payload, "text/event-stream")
        parts: list[str] = []
        finish: str | None = None
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT_SEC) as response:
                for raw in response:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                    except ValueError:
                        continue      # 주석·하트비트 줄. 스트림을 끊지 않음
                    for choice in chunk.get("choices") or []:
                        piece = (choice.get("delta") or {}).get("content")
                        if piece:
                            parts.append(str(piece))
                        finish = choice.get("finish_reason") or finish
        except urllib.error.HTTPError as exc:
            # 상태 코드와 서버가 준 사유를 남긴다. 'HTTPError' 만 보이면
            # 키·모델 이름·크레딧 중 무엇이 문제인지 알 수 없음
            # 응답 본문에는 우리 자격증명이 들어가지 않음 (요청 헤더는 남기지 않음)
            raise LlmError(f"LLM 호출 실패 HTTP {exc.code}: {_reason(exc)}") from exc
        except TimeoutError as exc:
            raise LlmError(_timeout_message()) from exc
        except (urllib.error.URLError, OSError) as exc:
            if isinstance(getattr(exc, "reason", None), TimeoutError):
                raise LlmError(_timeout_message()) from exc
            raise LlmError(f"LLM 호출 실패: {type(exc).__name__}") from exc
        return "".join(parts).strip(), finish


def _timeout_message() -> str:
    return (
        f"LLM 응답이 {_TIMEOUT_SEC}초 안에 끝나지 않았습니다."
        " 모델이 느리거나 요청이 너무 깁니다."
    )


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
        # user_message 는 서버가 준 한국어 안내. 화면에 그대로 노출됨
        return str(error.get("user_message") or error.get("message") or error)[:300]
    return str(error or data)[:300]

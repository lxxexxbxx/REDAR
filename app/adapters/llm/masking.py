"""식별자 마스킹 · 역치환 (docs/01 §7.4).

호스트·IP·경로를 TARGET_1 형태로 치환해 전송하고, 응답에서 되돌린다.
치환하지 않으면 내부 호스트명과 경로가 외부 API 로 나간다

응답 본문·추출값은 애초에 컨텍스트에 넣지 않는다. 마스킹은 2차 방어이며
1차 방어는 화이트리스트다 (narrative_service.build_context)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# 마스킹 대상. 경로는 호스트보다 먼저 치환한다 - URL 안의 호스트가 먼저 바뀌면
# 경로 패턴이 깨진다
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOSTNAME_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.I
)
_PATH_RE = re.compile(r"(?<![\w:])/[A-Za-z0-9._\-/]{2,}")

_PREFIX = {"target": "TARGET", "path": "PATH"}


@dataclass
class Masker:
    """치환 사전을 들고 있는 1회용 객체. 보고서 1건 안에서 일관된 번호를 쓴다"""

    mapping: dict[str, str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)

    def _token(self, kind: str, original: str) -> str:
        if original in self.mapping:
            return self.mapping[original]
        self._counters[kind] = self._counters.get(kind, 0) + 1
        token = f"{_PREFIX[kind]}_{self._counters[kind]}"
        self.mapping[original] = token
        return token

    def mask(self, text: str | None) -> str:
        """전송용 치환. None 은 빈 문자열"""
        if not text:
            return ""
        out = _URL_RE.sub(lambda m: self._token("target", m.group(0)), text)
        out = _IPV4_RE.sub(lambda m: self._token("target", m.group(0)), out)
        out = _HOSTNAME_RE.sub(lambda m: self._token("target", m.group(0)), out)
        return _PATH_RE.sub(lambda m: self._token("path", m.group(0)), out)

    def mask_context(self, context: dict[str, Any]) -> dict[str, Any]:
        return {key: self._mask_value(value) for key, value in context.items()}

    def _mask_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.mask(value)
        if isinstance(value, list):
            return [self._mask_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self._mask_value(v) for k, v in value.items()}
        return value

    def unmask(self, text: str | None) -> str:
        """응답 역치환. 긴 토큰을 먼저 되돌린다 - TARGET_1 이 TARGET_10 을 깨뜨린다"""
        if not text:
            return ""
        out = text
        for original, token in sorted(
            self.mapping.items(), key=lambda kv: len(kv[1]), reverse=True
        ):
            out = out.replace(token, original)
        return out

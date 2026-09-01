"""식별자 마스킹 · 역치환 (docs/01 §7.4).

호스트·IP·경로를 TARGET_1 형태로 치환해 전송하고, 응답에서 되돌림
치환하지 않으면 내부 호스트명과 경로가 외부 API 로 나감

응답 본문·추출값은 애초에 컨텍스트에 넣지 않음. 마스킹은 2차 방어이며
1차 방어는 화이트리스트 (remediation_service.report_context)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOSTNAME_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.I
)
_PATH_RE = re.compile(r"(?<![\w:])/[A-Za-z0-9._\-/]{2,}")

# 파일 확장자는 TLD 와 모양이 같다. 걸러내지 않으면 readme.html · wp-login.php 가
# 호스트로 치환돼 가이드가 조치 대상 파일명을 말하지 못함 (실측)
_FILE_SUFFIX = re.compile(
    r"\.(?:html?|php\d?|txt|xml|json|ya?ml|js|css|md|ini|conf|cfg|log|sql|"
    r"png|jpe?g|gif|svg|ico|zip|gz|tar|bak|old|sh|py|rb|pl|asp|aspx|jsp)$",
    re.I,
)
# 토큰이 다시 토큰 안에 들어가는 것을 막음. PATH_1 -> '/TARGET_1' 같은 중첩이 생기면
# 역치환 한 번으로 원문이 돌아오지 않아 응답에 TARGET_1 이 그대로 남음 (실측)
_TOKEN_RE = re.compile(r"\b(?:TARGET|PATH)_\d+\b")

_PREFIX = {"target": "TARGET", "path": "PATH"}


@dataclass
class Masker:
    """치환 사전을 들고 있는 1회용 객체. 보고서 1건 안에서 일관된 번호를 사용"""

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
        out = _HOSTNAME_RE.sub(self._host, out)
        return _PATH_RE.sub(self._path, out)

    def _host(self, match: re.Match[str]) -> str:
        value = match.group(0)
        # 파일명은 식별자가 아니다. 가려 봐야 얻는 것 없이 가이드만 못 쓰게 됨
        return value if _FILE_SUFFIX.search(value) else self._token("target", value)

    def _path(self, match: re.Match[str]) -> str:
        value = match.group(0)
        # 이미 치환된 토큰만 남은 경로는 다시 감싸지 않음 (중첩 방지)
        return value if _TOKEN_RE.fullmatch(value.lstrip("/")) \
            else self._token("path", value)

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
        """응답 역치환. 긴 토큰을 먼저 되돌림 - TARGET_1 이 TARGET_10 을 깨뜨림"""
        if not text:
            return ""
        out = text
        for original, token in sorted(
            self.mapping.items(), key=lambda kv: len(kv[1]), reverse=True
        ):
            out = out.replace(token, original)
        return out

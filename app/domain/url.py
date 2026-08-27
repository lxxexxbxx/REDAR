"""대상 URL 분해. host / port 를 확정값으로 확보.

nuclei 출력의 matched-at 은 'http://localhost:7860/api/v1/version' 형태이고
host 필드는 'localhost' 로 포트가 빠져 있어 한쪽만 믿을 수 없음.
fingerprint 가 host·port 를 분리해 받으므로 분해 실패를 조용히 넘기면 안 됨
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

# 스킴 기본 포트. 'http://h/x' 와 'http://h:80/x' 의 fingerprint 를 일치시키기 위해 보충
DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True, slots=True)
class UrlParts:
    scheme: str | None
    host: str
    port: int | None
    path: str


def parse(raw: str | None) -> UrlParts:
    """URL 또는 host[:port] 분해. 분해 불가 시 ValueError."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("빈 대상 문자열")

    # 'localhost:7860' 은 urlsplit 이 'localhost' 를 스킴으로 오인.
    # netloc 으로 읽히도록 '//' 를 보충
    if "//" not in text:
        text = "//" + text

    split = urlsplit(text)
    try:
        port = split.port
    except ValueError as exc:
        # 'http://h:abc/' 처럼 포트가 숫자가 아닌 경우
        raise ValueError(f"포트 해석 불가: {raw!r}") from exc

    host = split.hostname  # 소문자화됨. 호스트는 대소문자 구분 없음
    if not host:
        raise ValueError(f"호스트 없음: {raw!r}")

    scheme = split.scheme or None
    if port is None and scheme in DEFAULT_PORTS:
        port = DEFAULT_PORTS[scheme]

    return UrlParts(scheme=scheme, host=host, port=port, path=split.path)

"""스캔 간 동일 탐지 식별자.

    sha256(template_id | host | port | normalized_path | matcher_name)

오류 시 재스캔 비교에서 전 항목이 '신규 탐지'로 잡힘. 최빈 원인은 쿼리스트링 잔존 (docs/05 §7)
"""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

_SEP = "|"


def normalize_path(url_or_path: str | None) -> str:
    """URL 또는 경로 -> 정규화 경로.

    - 쿼리스트링 제거: `?page=1` 유무로 fingerprint 분기 시 비교 불가
    - 프래그먼트 제거: 서버 미전송, 탐지 동일성 무관
    - 후행 슬래시 제거: nuclei 가 같은 지점을 '/' 와 '' 로 혼용 보고. 루트는 빈 문자열
    - 대소문자 유지: 경로는 대소문자 구분
    """
    if not url_or_path:
        return ""
    return urlsplit(url_or_path).path.rstrip("/")


def make_fingerprint(
    template_id: str,
    host: str,
    port: int | None,
    url_or_path: str | None,
    matcher_name: str | None = None,
) -> str:
    parts = [
        template_id,
        host,
        "" if port is None else str(port),
        normalize_path(url_or_path),
        matcher_name or "",
    ]
    return hashlib.sha256(_SEP.join(parts).encode("utf-8")).hexdigest()

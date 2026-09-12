"""템플릿 표지 산출. 색인 시점 계산 후 저장 (절대규칙 7).

표지 = 템플릿이 어느 제품 전용인지. 환경 기반 제외의 유일한 판단 근거
"""
from __future__ import annotations

import re
from typing import Any

# WordPress 전용임을 뜻하는 태그. framework 필드가 없는 플러그인 템플릿이 다수
WP_TAGS = frozenset({"wordpress", "wp-plugin", "wp-theme", "woocommerce"})

_WP_ASSET_RE = re.compile(r"/wp-content/(?:plugins|themes)/([a-z0-9][a-z0-9._-]*)/", re.I)


def platform_of(metadata: dict[str, Any], tags: list[str]) -> str | None:
    """framework > WordPress 태그 > product. 없으면 None = 범용 = 항상 실행"""
    framework = str(metadata.get("framework") or "").strip().lower().replace("\\", "")
    if framework and framework != "-":
        return framework
    if WP_TAGS & set(tags):
        return "wordpress"
    product = str(metadata.get("product") or "").strip().lower()
    return product or None


def wp_component_slug(
    metadata: dict[str, Any], tags: list[str], raw_text: str
) -> str | None:
    """플러그인·테마 슬러그. namespace 누락 템플릿(5개 실측)은 요청 경로에서 추출"""
    if not {"wp-plugin", "wp-theme"} & set(tags):
        return None
    namespace = metadata.get("plugin_namespace")
    if namespace:
        return str(namespace).strip().lower()
    match = _WP_ASSET_RE.search(raw_text)
    return match.group(1).lower() if match else None

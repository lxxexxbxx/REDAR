"""nuclei detection finding -> 환경 프로필. 순수 함수.

tech-detect(Wappalyzer) 는 탐지 집합을 넓히기만 함. 애플리케이션 확정에 쓰면
jquery 하나로 '정체 확인' 이 되어 환경 기반 제외가 발동함 (미탐지 위험)
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3}[a-z0-9]*)", re.IGNORECASE)
_SUFFIXES = ("-detect", "-detection", "-version", "-panel", "-login")
_WEB_SERVERS = (
    "http_server",
    "apache",
    "nginx",
    "iis",
    "litespeed",
    "openresty",
    "lighttpd",
    "caddy",
    "tomcat",
    "jetty",
    "tengine",
)
_LANGUAGES = ("php", "python", "node.js", "asp.net", "java", "ruby")
# 애플리케이션 선정 우선순위. 조치 가이드의 주 대상
_CMS = (
    "wordpress",
    "joomla",
    "drupal",
    "magento",
    "prestashop",
    "typo3",
    "moodle",
    "opencart",
    "ghost",
)
# 매처 이름이 곧 슬러그인 범용 탐지 템플릿
_GENERIC_WP = {
    "wordpress-plugin-detect": "wp_plugin",
    "wordpress-theme-detect": "wp_theme",
}


@dataclass(frozen=True)
class DetectionHit:
    template_id: str
    matcher_name: str | None
    extracted: tuple[str, ...]
    platform: str | None
    tags: tuple[str, ...]
    component_slug: str | None


@dataclass
class TechProfile:
    stack: dict[str, dict[str, Any]] = field(default_factory=dict)
    components: list[dict[str, Any]] = field(default_factory=list)
    detected: frozenset[str] = frozenset()

    @property
    def app_identified(self) -> bool:
        return "application" in self.stack


def _version(values: Sequence[str]) -> str | None:
    for value in values:
        match = _VERSION_RE.search(value or "")
        if match:
            return match.group(1)
    return None


def _product(hit: DetectionHit) -> str:
    if hit.platform:
        return hit.platform
    name = hit.template_id.lower()
    for suffix in _SUFFIXES:
        name = name.removesuffix(suffix)
    return name


def _component(
    ctype: str, slug: str, version: str | None, evidence: str
) -> dict[str, Any]:
    return {
        "type": ctype,
        "slug": slug,
        "name": None,
        "version": version,
        "active": None,
        # 버전을 못 읽으면 존재만 확인. 추정값 확정 표기 금지 (M4 규칙 3)
        "confidence": "high" if version else "medium",
        "evidence": evidence,
    }


def _wp_type(tags: tuple[str, ...]) -> str | None:
    if "wp-plugin" in tags:
        return "wp_plugin"
    if "wp-theme" in tags:
        return "wp_theme"
    return None


def build(hits: Sequence[DetectionHit]) -> TechProfile:
    detected: set[str] = set()
    components: dict[tuple[str, str], dict[str, Any]] = {}
    products: dict[str, dict[str, Any]] = {}

    for hit in hits:
        evidence = f"nuclei {hit.template_id}"
        if hit.platform:
            detected.add(hit.platform)

        if hit.template_id == "tech-detect":
            if hit.matcher_name:
                name = hit.matcher_name.lower()
                detected.add(name)
                components.setdefault(
                    ("tech", name), _component("tech", name, None, evidence)
                )
            continue

        if hit.template_id in _GENERIC_WP and hit.matcher_name:
            ctype = _GENERIC_WP[hit.template_id]
            slug = hit.matcher_name.lower()
            components.setdefault(
                (ctype, slug), _component(ctype, slug, None, evidence)
            )
            continue

        wp_type = _wp_type(hit.tags)
        if wp_type and hit.component_slug:
            version = _version(hit.extracted)
            if hit.matcher_name == "outdated_version":
                evidence += " · 최신 버전보다 낮음"
            key = (wp_type, hit.component_slug)
            if key not in components or (version and not components[key]["version"]):
                components[key] = _component(
                    wp_type, hit.component_slug, version, evidence
                )
            continue

        product = _product(hit)
        detected.add(product)
        version = _version(hit.extracted)
        current = products.get(product)
        if current is None or (version and not current["version"]):
            products[product] = {
                "product": product,
                "version": version,
                "confidence": "high" if version else "medium",
                "evidence": evidence,
            }

    stack: dict[str, dict[str, Any]] = {}
    rest: list[str] = []
    for name in sorted(products):
        if "web_server" not in stack and any(k in name for k in _WEB_SERVERS):
            stack["web_server"] = products[name]
        elif "language" not in stack and name in _LANGUAGES:
            stack["language"] = products[name]
        else:
            rest.append(name)

    if rest:
        # 결정론: CMS -> 버전 확인된 제품 -> 사전순
        app = (
            next((n for c in _CMS for n in rest if c in n), None)
            or next((n for n in rest if products[n]["version"]), None)
            or rest[0]
        )
        stack["application"] = products[app]
        for name in rest:
            if name != app:
                p = products[name]
                components.setdefault(
                    ("tech", name),
                    _component("tech", name, p["version"], p["evidence"]),
                )

    return TechProfile(
        stack=stack,
        components=sorted(components.values(), key=lambda c: (c["type"], c["slug"])),
        detected=frozenset(detected),
    )

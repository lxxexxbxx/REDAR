"""환경 기반 템플릿 제외 계산. 순수 함수 (main_pass_files 의 디렉터리 조회 제외).

원칙: 미탐지 0 이 1순위. 조건 하나라도 애매하면 유지.
어휘 통일 - 탐지 집합과 관측 가능 집합이 모두 템플릿 표지(platform)에서 나오므로
'apache' 와 'http_server' 같은 표시명 불일치로 오제외되지 않음
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# 대상 전 경로를 무차별 조회하는 열거 템플릿. 취약점 판정 없음, 요청의 76% (실측)
ENUMERATOR_IDS = ("wordpress-plugins-detect", "wordpress-themes-detect")

_PREPASS_DIRS = ("/http/technologies/", "/http/exposed-panels/")

# 리버스 프록시·CDN 뒤에서 앞단만 보이는 계층. 미탐지여도 존재 가능
_SERVER_LAYER = (
    "http_server", "apache", "tomcat", "iis", "internet_information", "jetty",
    "weblogic", "jboss", "wildfly", "websphere", "glassfish", "nginx", "openresty",
    "lighttpd", "caddy", "tengine", "litespeed", "resin", "undertow", "php",
    "node.js", "express", "openssl", "traefik", "haproxy", "envoy", "varnish", "squid",
)

# 템플릿 트리 중 템플릿이 아닌 곳. 워드리스트·스캔 프로필
_NON_TEMPLATE_TOP = {"helpers", "profiles"}


@dataclass(frozen=True)
class TemplateMeta:
    template_id: str
    file_path: str
    source: str
    tags: tuple[str, ...]
    platform: str | None


@dataclass(frozen=True)
class TargetEnv:
    detected: frozenset[str]
    app_identified: bool


@dataclass(frozen=True)
class ExclusionPlan:
    excluded: tuple[TemplateMeta, ...]
    fallback_reason: str | None

    def by_platform(self) -> list[dict[str, Any]]:
        counts = Counter(m.platform for m in self.excluded)
        return [{"platform": p, "templates": n} for p, n in sorted(counts.items())]


def normalize_path(path: str) -> str:
    return str(path).replace("\\", "/").lower()


def is_prepass(meta: TemplateMeta) -> bool:
    """사전 패스 대상 = 제품 식별 템플릿 (technologies ∪ exposed-panels ∪ tags:tech)"""
    if meta.source != "official":
        return False
    path = normalize_path(meta.file_path)
    return any(d in path for d in _PREPASS_DIRS) or "tech" in meta.tags


def is_server_layer(platform: str) -> bool:
    return any(key in platform for key in _SERVER_LAYER)


def _matches(platform: str, detected: frozenset[str]) -> bool:
    return any(d and (d in platform or platform in d) for d in detected)


def decide(metas: Sequence[TemplateMeta], envs: Sequence[TargetEnv]) -> ExclusionPlan:
    if not metas:
        return ExclusionPlan((), "no_index")
    if not envs or not all(env.app_identified for env in envs):
        # 한 대상이라도 정체 불명이면 그 대상은 전부 필요. 합집합이라 제외 불가
        return ExclusionPlan((), "no_application")
    observable = {m.platform for m in metas if is_prepass(m) and m.platform}
    excluded = tuple(
        m for m in metas
        if m.source == "official"
        and m.platform
        and not is_prepass(m)
        # 탐지 수단이 없는 제품은 '미탐지' 가 곧 '부재' 가 아님
        and m.platform in observable
        and not is_server_layer(m.platform)
        and not any(_matches(m.platform, env.detected) for env in envs)
    )
    return ExclusionPlan(excluded, None)


def main_pass_files(official_dir: Path, skip: set[str]) -> list[str]:
    """본 패스 목록 = 디스크의 템플릿 전부 - skip.

    색인이 아니라 디스크 기준인 이유: 수동 반입 등 색인에 없는 파일이 조용히 빠지지 않음
    """
    if not official_dir.is_dir():
        return []
    files = []
    for path in sorted(official_dir.rglob("*.yaml")):
        rel = path.relative_to(official_dir).parts
        if rel[0] in _NON_TEMPLATE_TOP or any(part.startswith(".") for part in rel):
            continue
        if normalize_path(str(path)) not in skip:
            files.append(str(path))
    return files

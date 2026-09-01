"""환경 조사 흐름 제어. HTTP 객체 참조 없음 (docs/01 §2.1).

수집기 실패는 스캔 중단 사유가 아님. collectors_failed 에 남기고 계속 (M4 규칙 2)
"""
from __future__ import annotations

import logging
import sqlite3
from dataclasses import asdict, dataclass, field
from typing import Any

from app.collectors import base as collectors
from app.domain import url as urlmod
from app.domain.ids import new_id
from app.repository import environment as env_repo

logger = logging.getLogger(__name__)

# 스택 필드별로 어느 수집기를 신뢰할지. 뒤에 오는 수집기가 앞을 덮어쓸 조건은
# '더 구체적인 값을 가졌을 때' 뿐. 빈 값으로 덮으면 앞선 탐지가 사라짐
_STACK_FIELDS = ("web_server", "language", "application")


@dataclass
class EnvironmentResult:
    profile_id: str
    target_host: str
    stack: dict[str, dict[str, Any]] = field(default_factory=dict)
    components: list[dict[str, Any]] = field(default_factory=list)
    exposures: list[dict[str, Any]] = field(default_factory=list)
    collectors_run: list[str] = field(default_factory=list)
    collectors_failed: list[str] = field(default_factory=list)


def collect_target(
    conn: sqlite3.Connection,
    scan_id: str,
    target: str,
    *,
    timeout_sec: int = 5,
    http=None,
) -> EnvironmentResult:
    """대상 1개 조사 후 저장. 예외를 밖으로 내보내지 않음"""
    parsed = urlmod.parse(target)
    ctx = collectors.TargetContext(
        # 스킴 없는 'host:port' 입력은 평문으로 봄. https 를 가정하면 TLS 판정이 왜곡
        scheme=parsed.scheme or "http",
        host=parsed.host,
        port=parsed.port,
        timeout_sec=timeout_sec,
        http=http,
    )

    result = EnvironmentResult(profile_id=new_id("env"), target_host=ctx.target_host)
    for collector in collectors.registry():
        try:
            if not collector.applicable(ctx):
                continue
            collected = collector.collect(ctx)
        except Exception:  # noqa: BLE001 - 수집기 하나가 스캔을 죽이면 안 됨
            logger.warning("수집기 실패: %s", collector.key, exc_info=True)
            result.collectors_failed.append(collector.key)
            continue
        ctx.collected[collector.key] = collected
        result.collectors_run.append(collector.key)
        _merge(result, collected)

    env_repo.save_profile(
        conn,
        profile_id=result.profile_id,
        scan_id=scan_id,
        target_host=result.target_host,
        stack=result.stack,
        components=result.components,
        exposures=result.exposures,
        collectors_run=result.collectors_run,
        collectors_failed=result.collectors_failed,
    )
    return result


def _merge(result: EnvironmentResult, collected: collectors.CollectResult) -> None:
    for name in _STACK_FIELDS:
        found = getattr(collected, name)
        if found is None or found.product is None:
            continue
        current = result.stack.get(name)
        # 버전을 가진 값이 없는 값을 이김. 같은 조건이면 먼저 온 수집기 유지
        if current is None or (not current.get("version") and found.version):
            result.stack[name] = _stack_dict(found)

    seen = {(c["type"], c["slug"]) for c in result.components}
    for component in collected.components:
        key = (component.type, component.slug)
        if key not in seen:
            seen.add(key)
            result.components.append(_component_dict(component))

    known = {e["key"] for e in result.exposures}
    for exposure in collected.exposures:
        if exposure.key not in known:
            known.add(exposure.key)
            result.exposures.append(asdict(exposure))


def _stack_dict(found: collectors.StackFinding) -> dict[str, Any]:
    return {
        "product": found.product,
        "version": found.version,
        "confidence": str(found.confidence),
        "evidence": found.evidence,
    }


def _component_dict(found: collectors.ComponentFinding) -> dict[str, Any]:
    data = asdict(found)
    data["confidence"] = str(found.confidence)
    return data


# ────────────────────────────────────────── environment_driven 선별

@dataclass
class Selection:
    """선별 결과 + 근거. basis 는 scans.selection_basis 에 JSON 으로 저장됨"""

    template_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    basis: dict[str, Any] = field(default_factory=dict)


# 탐지된 제품 -> nuclei 태그. 인벤토리가 비어 있어도 스캔이 성립하는 경로.
# 제품 문자열은 수집기마다 다름 ('Apache' / 'Apache httpd') 이므로 부분 일치로 찾음
_PRODUCT_TAGS = (
    ("wordpress", "wordpress"),
    ("apache", "apache"),
    ("nginx", "nginx"),
    ("php", "php"),
    ("tomcat", "tomcat"),
)


def _tag_for(product: str) -> str | None:
    lowered = product.lower()
    return next((tag for needle, tag in _PRODUCT_TAGS if needle in lowered), None)


def select_templates(
    conn: sqlite3.Connection, results: list[EnvironmentResult]
) -> Selection:
    """환경 조사 결과를 기록. **템플릿을 걸러내지 않는다**

    이전에는 탐지된 구성요소·스택으로 -id 와 -tags 를 만들어 넘겼다. 두 가지 문제:

      1. nuclei 는 서로 다른 필터를 AND 로 묶는다. -id(플러그인 CVE 몇 건) 와
         -tags(wordpress) 를 함께 주면 교집합만 남아 사실상 아무것도 안 돈다.
         실제로 WordPress 대상은 취약 버전인데도 0건, 아무것도 탐지되지 않아
         필터가 비었던 Langflow 대상만 검출되는 비대칭이 나타났다
      2. 진단 도구에서 선별로 놓치는 것은 시간을 아끼는 것보다 훨씬 나쁘다

    이제 보유 템플릿 전부를 실행하고, 환경 조사 결과는 보고서 근거로만 쓴다.
    범위를 좁히려면 사용자가 '조건 필터 선별' 을 직접 고른다
    """
    slugs = sorted({
        c["slug"] for r in results for c in r.components
        if c["type"] in ("wp_plugin", "wp_theme")
    })
    by_slug = env_repo.advisory_templates(conn, slugs)

    matched_components = [
        {
            "slug": slug,
            "version": _version_of(results, slug),
            "templates": templates,
        }
        for slug, templates in sorted(by_slug.items())
    ]

    matched_stack: list[dict[str, Any]] = []
    tags: list[str] = []
    for result in results:
        for name in _STACK_FIELDS:
            item = result.stack.get(name)
            if not item or not item.get("product"):
                continue
            tag = _tag_for(item["product"])
            if tag and tag not in tags:
                tags.append(tag)
            entry = {
                "product": item["product"],
                "version": item.get("version"),
                "templates": [],
            }
            if entry not in matched_stack:
                matched_stack.append(entry)

    candidates = sorted({t for templates in by_slug.values() for t in templates})
    available = env_repo.local_template_count(conn)
    # 인벤토리에 있는 것만 실행 대상. 비어 있으면 태그가 스캔을 이끔
    selected = env_repo.templates_for_ids(conn, candidates)

    return Selection(
        # 필터를 넘기지 않음 = 보유 템플릿 전부 실행
        template_ids=[],
        tags=[],
        basis={
            "matched_components": matched_components,
            "matched_stack": matched_stack,
            # 전부 실행하므로 선별 수는 곧 보유 수
            "total_selected": available,
            "total_available": available,
            "universe": "templates",
            # 환경에서 도출된 후보. 실행 범위를 좁히는 데는 쓰지 않고 근거로만 남김
            "candidate_templates": len(candidates),
            "environment_templates": selected,
            "environment_tags": tags,
            "filtered": False,
        },
    )


def _version_of(results: list[EnvironmentResult], slug: str) -> str | None:
    for result in results:
        for component in result.components:
            if component["slug"] == slug and component.get("version"):
                return component["version"]
    return None

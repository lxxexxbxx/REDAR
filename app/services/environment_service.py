"""환경 조사 흐름 제어. HTTP 객체 참조 없음 (docs/01 §2.1).

제품·버전 식별은 nuclei detection finding, 자체 수집기는 노출 점검 전담 (docs/01 §4.1)
수집기 실패는 스캔 중단 사유가 아님. collectors_failed 에 남기고 계속 (M4 규칙 2)
"""
from __future__ import annotations

import logging
import sqlite3
from dataclasses import asdict, dataclass, field
from typing import Any

from app.collectors import base as collectors
from app.domain import tech_profile
from app.domain import url as urlmod
from app.domain.ids import new_id
from app.domain.template_exclusion import TemplateMeta, is_prepass
from app.repository import environment as env_repo

logger = logging.getLogger(__name__)

# 스택 필드별로 어느 수집기를 신뢰할지. 뒤에 오는 수집기가 앞을 덮어쓸 조건은
# '더 구체적인 값을 가졌을 때' 뿐. 빈 값으로 덮으면 앞선 탐지가 사라짐
_STACK_FIELDS = ("web_server", "language", "application")
_DEFAULT_PORT = {"http": 80, "https": 443}
_RANK = {"high": 3, "medium": 2, "low": 1}


@dataclass
class EnvironmentResult:
    profile_id: str
    target_host: str
    stack: dict[str, dict[str, Any]] = field(default_factory=dict)
    components: list[dict[str, Any]] = field(default_factory=list)
    exposures: list[dict[str, Any]] = field(default_factory=list)
    collectors_run: list[str] = field(default_factory=list)
    collectors_failed: list[str] = field(default_factory=list)


def host_key(target: str) -> str:
    """대상 식별 키. finding 은 포트를 채우고 입력은 비우는 경우가 있어 기본 포트로 맞춤"""
    parsed = urlmod.parse(target)
    port = parsed.port or _DEFAULT_PORT.get(parsed.scheme or "http", 80)
    return f"{parsed.host}:{port}"


def tech_profiles(
    conn: sqlite3.Connection, scan_id: str
) -> dict[str, tech_profile.TechProfile]:
    """스캔의 detection finding 을 대상별 환경 프로필로. 사전 패스 집합만 해석

    취약점 템플릿 결과까지 환경 근거로 쓰면 CVE 매칭이 '제품 탐지' 로 둔갑함
    """
    grouped: dict[str, list[tech_profile.DetectionHit]] = {}
    for row in env_repo.detection_rows(conn, scan_id):
        meta = TemplateMeta(
            row["template_id"], row["file_path"], row["source"],
            tuple(row["tags"]), row["platform"],
        )
        if not is_prepass(meta):
            continue
        port = row["target_port"] or _DEFAULT_PORT.get(row["target_scheme"] or "http", 80)
        grouped.setdefault(f"{row['target_host']}:{port}", []).append(
            tech_profile.DetectionHit(
                template_id=row["template_id"],
                matcher_name=row["matcher_name"],
                extracted=tuple(row["ev_extracted"]),
                platform=row["platform"],
                tags=tuple(row["tags"]),
                component_slug=row["component_slugs"],
            )
        )
    return {key: tech_profile.build(hits) for key, hits in grouped.items()}


def collect_target(
    conn: sqlite3.Connection,
    scan_id: str,
    target: str,
    *,
    timeout_sec: int = 5,
    http=None,
    tech: tech_profile.TechProfile | None = None,
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
        detected=tech.detected if tech else frozenset(),
    )

    result = EnvironmentResult(profile_id=new_id("env"), target_host=ctx.target_host)
    for collector in collectors.registry():
        try:
            if not collector.applicable(ctx):
                continue
            collected = collector.collect(ctx)
        except Exception:
            logger.warning("수집기 실패: %s", collector.key, exc_info=True)
            result.collectors_failed.append(collector.key)
            continue
        ctx.collected[collector.key] = collected
        result.collectors_run.append(collector.key)
        _merge(result, collected)

    if tech is not None:
        _merge_tech(result, tech)

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


def _merge_tech(result: EnvironmentResult, tech: tech_profile.TechProfile) -> None:
    """nuclei 결과 병합. 버전을 가졌거나 확신도가 높은 쪽이 이김"""
    for name, found in tech.stack.items():
        current = result.stack.get(name)
        if current is None or _better(found, current):
            result.stack[name] = dict(found)
    index = {(c["type"], c["slug"]): i for i, c in enumerate(result.components)}
    for comp in tech.components:
        key = (comp["type"], comp["slug"])
        if key not in index:
            index[key] = len(result.components)
            result.components.append(dict(comp))
        elif _better(comp, result.components[index[key]]):
            result.components[index[key]] = dict(comp)


def _better(new: dict[str, Any], old: dict[str, Any]) -> bool:
    if new.get("version") and not old.get("version"):
        return True
    if old.get("version") and not new.get("version"):
        return False
    return _RANK.get(str(new.get("confidence")), 0) > _RANK.get(str(old.get("confidence")), 0)


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

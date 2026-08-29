"""가이드 매핑 엔진 (docs/03 §3, §5).

탐지 결과와 환경 조사 결과를 가이드 점검항목에 연결하고 판정함
가이드 본문(guide_items)이 없어도 동작해야 한다 - 매핑 테이블은 번들이고
finding_guide_refs.item_code 에 FK 가 없다 (절대규칙 3)
"""
from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from typing import Any

from app.domain.enums import GuideVerdict
from app.repository import environment as env_repo
from app.repository import guide as guide_repo

logger = logging.getLogger(__name__)

# 우선순위. 상위에서 매칭되면 하위는 적용하지 않음 (docs/03 §3.1).
# 같은 층에서는 복수 매칭을 허용함
PRIORITY = (
    "template_id",
    "cve_id",
    "cwe_id",
    "exposure_key",
    "component_slug",
    "vuln_type",
)

# 우선순위 규칙 밖의 예외. CVE 를 가진 탐지에 항상 추가되며 is_primary=0 임
# 유형 트랙만 두면 '버전 올리기' 가 사라지고, 패치 트랙만 두면 모든 CVE 가
# WEB-25 하나로 수렴해 유형별 조치가 없어짐 (docs/03 §3.1.1)
MATCH_CVE_PRESENT = "cve_present"


@dataclass(frozen=True)
class MappingResult:
    findings_mapped: int
    refs_written: int
    skipped_detection: int


def map_scan(conn: sqlite3.Connection, scan_id: str) -> MappingResult:
    """스캔의 탐지 결과를 점검항목에 연결. 재실행 안전"""
    rules = guide_repo.load_mappings(conn)
    findings = guide_repo.mappable_findings(conn, scan_id)
    skipped = guide_repo.detection_finding_count(conn, scan_id)

    rows: list[tuple[str, str, str, int, str]] = []
    mapped = 0
    for finding in findings:
        refs = resolve(finding, rules)
        if refs:
            mapped += 1
        for ref in refs:
            rows.append((
                finding["finding_id"], ref["item_code"], ref["confidence"],
                int(ref["is_primary"]), ref["matched_by"],
            ))

    guide_repo.replace_refs(conn, scan_id, rows)
    return MappingResult(
        findings_mapped=mapped, refs_written=len(rows), skipped_detection=skipped
    )


def resolve(
    finding: dict[str, Any], rules: dict[str, dict[str, list[dict[str, Any]]]]
) -> list[dict[str, Any]]:
    """finding 1건의 점검항목 목록. 우선순위 첫 매칭 층만 is_primary=1"""
    refs: list[dict[str, Any]] = []
    seen: set[str] = set()

    for match_type in PRIORITY:
        hits = _hits(match_type, finding, rules)
        if not hits:
            continue
        for hit in hits:
            if hit["item_code"] in seen:
                continue
            seen.add(hit["item_code"])
            refs.append({**hit, "is_primary": True})
        break                       # 상위 층에서 매칭되면 하위는 적용하지 않는다

    # 2트랙. CVE 가 있으면 패치 항목을 항상 추가 (is_primary=0)
    cves = _values(finding, "cve_ids")
    if cves:
        for hit in rules.get(MATCH_CVE_PRESENT, {}).get("*", []):
            if hit["item_code"] in seen:
                continue
            seen.add(hit["item_code"])
            refs.append({
                **hit,
                "is_primary": False,
                "matched_by": f"{MATCH_CVE_PRESENT}:{cves[0]}",
            })
    return refs


def _hits(
    match_type: str,
    finding: dict[str, Any],
    rules: dict[str, dict[str, list[dict[str, Any]]]],
) -> list[dict[str, Any]]:
    table = rules.get(match_type) or {}
    if not table:
        return []

    if match_type == "template_id":
        keys = [finding.get("template_id")]
    elif match_type == "cve_id":
        keys = _values(finding, "cve_ids")
    elif match_type == "cwe_id":
        keys = _values(finding, "cwe_ids")
    elif match_type == "component_slug":
        keys = [finding.get("component_slug")]
    elif match_type == "vuln_type":
        keys = [finding.get("vuln_type")]
    elif match_type == "exposure_key":
        # 노출 항목은 finding 이 아니라 환경 조사에서 판정 (verdicts 참조)
        return []
    else:
        keys = []

    out: list[dict[str, Any]] = []
    for key in keys:
        if not key:
            continue
        for rule in table.get(str(key), []):
            out.append({**rule, "matched_by": f"{match_type}:{key}"})
    return out


def _values(finding: dict[str, Any], column: str) -> list[str]:
    raw = finding.get(column)
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(v) for v in raw if v]
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(v) for v in parsed if v] if isinstance(parsed, list) else []


# ────────────────────────────────────────────── 판정 (docs/03 §5.1)

# 점검 가능 근거가 없으면 safe 로 두지 않음. '점검하지 않은 것' 이
# '양호' 로 둔갑하는 것이 보고서에서 가장 위험한 오류 (절대규칙 10)
_UNCHECKED_NOTE = "점검 범위 외 — 원격 스캔으로 확인할 수 없는 항목"
_EXPOSURE_SAFE_NOTE = "환경 조사에서 확인됨 · 노출 없음"
_FINDING_SAFE_NOTE = "점검 대상 스택 확인됨 · 탐지 없음"


@dataclass(frozen=True)
class ItemVerdict:
    item_code: str
    verdict: GuideVerdict
    basis: str
    finding_count: int = 0


def verdicts(conn: sqlite3.Connection, scan_id: str) -> list[ItemVerdict]:
    """점검항목별 판정. 매핑이 있는 항목 전부를 대상으로 함

    0건인 항목이 목록에서 사라지면 보고서 목차가 대상마다 달라짐 (절대규칙 4)
    """
    rules = guide_repo.load_mappings(conn)
    counts = guide_repo.ref_counts(conn, scan_id)

    exposures: dict[str, dict[str, Any]] = {}
    for profile in env_repo.profiles(conn, scan_id):
        for exposure in profile["exposures"]:
            # 대상이 여러 개면 하나라도 노출이면 노출로 봄
            previous = exposures.get(exposure["key"])
            if previous is None or (exposure["value"] and not previous["value"]):
                exposures[exposure["key"]] = exposure

    # 환경 조사에서 확인된 스택. safe 판정을 허용할 근거 (docs/03 §5.1)
    stack_known = any(
        (profile.get(field) or {}).get("product")
        for profile in env_repo.profiles(conn, scan_id)
        for field in ("web_server", "language", "application")
    )

    exposure_items: dict[str, list[str]] = {}
    for value, entries in (rules.get("exposure_key") or {}).items():
        for entry in entries:
            exposure_items.setdefault(entry["item_code"], []).append(value)

    out: list[ItemVerdict] = []
    for item_code in guide_repo.mapped_item_codes(conn):
        count = counts.get(item_code, 0)
        if count:
            out.append(ItemVerdict(
                item_code, GuideVerdict.VULNERABLE,
                f"매핑된 탐지 {count}건", count,
            ))
            continue

        keys = exposure_items.get(item_code) or []
        checked = [exposures[k] for k in keys if k in exposures]
        if checked:
            if any(e["value"] for e in checked):
                out.append(ItemVerdict(
                    item_code, GuideVerdict.VULNERABLE,
                    "환경 조사 노출 확인: "
                    + ", ".join(e["key"] for e in checked if e["value"]),
                ))
            else:
                out.append(ItemVerdict(
                    item_code, GuideVerdict.SAFE, _EXPOSURE_SAFE_NOTE
                ))
            continue

        if keys:
            # 매핑은 노출 기준인데 그 노출을 수집하지 못함 -> 점검하지 않음
            out.append(ItemVerdict(
                item_code, GuideVerdict.NOT_APPLICABLE,
                f"{_UNCHECKED_NOTE} (미수집: {', '.join(sorted(keys))})",
            ))
            continue

        out.append(
            ItemVerdict(item_code, GuideVerdict.SAFE, _FINDING_SAFE_NOTE)
            if stack_known
            else ItemVerdict(item_code, GuideVerdict.NOT_APPLICABLE, _UNCHECKED_NOTE)
        )
    return out


def summary(items: list[ItemVerdict]) -> dict[str, int]:
    """판정 집계. 0건 판정도 키를 유지 (절대규칙 4)"""
    counts = {verdict.value: 0 for verdict in GuideVerdict}
    for item in items:
        counts[item.verdict.value] += 1
    return counts

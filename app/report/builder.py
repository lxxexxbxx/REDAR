"""Report JSON 조립 (docs/00 §1.3, docs/04 §3).

여기서 보고서가 완결. 렌더러는 이 JSON 만 받아 파일을 만들고 어떤 판단도 하지
않음 - 렌더러가 DB 를 조회하면 GUI 미리보기와 파일 산출물이 갈라짐

골격은 findings 유무와 무관하게 고정. 0건이면 count: 0 · 빈 배열이며
섹션이 사라지지 않음 (절대규칙 4)
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from app import __version__
from app.domain import severity as severity_mod
from app.domain.enums import (
    SEVERITY_LABELS,
    VULN_TYPE_LABELS,
    Severity,
    VulnType,
)
from app.report import fallback
from app.repository import environment as env_repo
from app.repository import guide as guide_repo
from app.repository import reports as report_repo
from app.repository import scans as scan_repo
from app.services import guide_service

# 보고서에 싣는 응답 원문 상한. 초과분은 마커로 절단 표시 (docs/04)
EVIDENCE_LIMIT = 2 * 1024
TRUNCATION_MARKER = "…이하 생략"
TOP_RISK_LIMIT = 5
HOSTS_INLINE_LIMIT = 10


def build(
    conn: sqlite3.Connection,
    scan_id: str,
    *,
    report_id: str,
    include_evidence: bool = True,
    exclude_false_positives: bool = True,
) -> dict[str, Any]:
    """스캔 1건의 Report JSON. **완전히 결정론적.** LLM 이 개입하지 않음

    같은 스캔에 항상 같은 보고서가 나와야 근거 대조가 가능하다.
    LLM 조치 가이드는 이 JSON 을 입력으로 받는 별도 기능이며 보고서를 바꾸지 않음
    """
    scan = scan_repo.get_scan(conn, scan_id)
    if scan is None:
        raise ValueError(f"스캔 없음: {scan_id}")

    findings = report_repo.findings_for_report(
        conn, scan_id, exclude_false_positives=exclude_false_positives
    )
    false_positives = report_repo.false_positives(conn, scan_id)
    guide_status = guide_repo.status(conn)
    profiles = env_repo.profiles(conn, scan_id)

    by_severity = _count(findings, "severity", [s.value for s in Severity])
    by_vuln_type = _count(findings, "vuln_type", [v.value for v in VulnType])

    detail = [_finding_block(f, include_evidence=include_evidence) for f in findings]
    verdicts = guide_service.verdicts(conn, scan_id)
    guide_items = report_repo.guide_items_for_scan(conn, scan_id)

    return {
        "report_id": report_id,
        "scan_id": scan_id,
        "generated_at": None,          # 저장 시점에 채운다
        "meta": _meta(scan, profiles, guide_status),
        "executive_summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_vuln_type": by_vuln_type,
            "top_risks": _top_risks(findings),
            "narrative": fallback.executive_summary(len(findings), by_severity),
            "narrative_generated_by": fallback.GENERATED_BY_TEMPLATE,
        },
        # 대상 여러 개면 프로필도 여러 개. 첫 대상을 대표로 두고 전체는 environment_profiles
        "environment_profile": profiles[0] if profiles else None,
        "environment_profiles": profiles,
        "findings_by_severity": [
            {
                "severity": s.value,
                "label": SEVERITY_LABELS[s],
                "count": by_severity[s.value],
                "findings": [f["finding_id"] for f in findings if f["severity"] == s.value],
            }
            for s in Severity
        ],
        "findings_by_vuln_type": [
            {
                "vuln_type": v.value,
                "label": VULN_TYPE_LABELS[v],
                "count": by_vuln_type[v.value],
                "findings": [
                    f["finding_id"] for f in findings if f["vuln_type"] == v.value
                ],
            }
            for v in VulnType
        ],
        "findings_detail": detail,
        "remediation": _remediation(conn, scan_id, findings, guide_items),
        "patch_plan": _patch_plan(conn, scan_id),
        "guide_mapping": _guide_mapping(verdicts, guide_items, guide_status),
        "unmapped_findings": _unmapped(conn, scan_id, findings),
        "false_positives": [
            {
                "finding_id": f["finding_id"], "name": f["name"],
                "severity": f["severity"], "note": f["status_note"],
            }
            for f in false_positives
        ],
        "appendix": _appendix(conn, scan_id),
    }


# ────────────────────────────────────────────── 구성 요소

def _count(rows: list[dict[str, Any]], column: str, keys: list[str]) -> dict[str, int]:
    """축을 고정한 집계. 0건 키가 사라지면 보고서 목차가 대상마다 달라짐"""
    counts = {key: 0 for key in keys}
    for row in rows:
        value = row.get(column)
        if value in counts:
            counts[value] += 1
    return counts


def _meta(
    scan: dict[str, Any],
    profiles: list[dict[str, Any]],
    guide_status: dict[str, Any],
) -> dict[str, Any]:
    hosts = scan.get("targets") or []
    # 입력 원문. 포트 범위는 전개 전 표기를 개요에 남김
    requested = scan.get("target_input") or hosts
    probe = scan.get("target_probe") or {}
    # 보고서에는 실제로 응답한 대상만 싣는다. 닫힌 포트를 나열하면
    # 조치와 무관한 수백 줄이 되고, 요청 수만 적으면 점검 범위가 과장된다
    scanned = probe.get("responded") or hosts
    return {
        "target_summary": _target_summary(requested, len(scanned)),
        # 실제 스캔한 대상. 조치 대상이 특정되어야 하므로 전개 결과를 그대로 둠
        "targets": scanned,
        "target_input": requested,
        "target_probe": {
            "requested": probe.get("requested", len(hosts)),
            "scanned": len(scanned),
            # 확인하지 않은 스캔(이전 버전)은 0. 요청 전부를 스캔한 것으로 본다
            "no_response": len(probe.get("no_response") or []),
        },
        "scan_started_at": scan.get("started_at") or scan.get("created_at"),
        "scan_finished_at": scan.get("finished_at"),
        "scan_duration_sec": scan.get("duration_sec"),
        "tool_version": scan.get("tool_version") or __version__,
        "nuclei_version": scan.get("nuclei_version"),
        "template_revision": scan.get("template_revision"),
        "selection_mode": (scan.get("template_selection") or {}).get("mode"),
        "guide_db": {
            "imported": guide_status["imported"],
            "version": guide_status["version"],
            "item_count": guide_status["item_count"],
        },
        "guide_coverage": {
            "items_total": guide_status["item_count"],
            "items_covered": guide_status["items_covered"],
        },
        # environment_driven 이 아니면 None. 값이 없어도 A-2 절은 렌더링됨
        "selection_basis": scan.get("selection_basis"),
        "collectors": {
            "run": sorted({c for p in profiles for c in p["collectors_run"]}),
            "failed": sorted({c for p in profiles for c in p["collectors_failed"]}),
        },
        # 보고서에는 LLM 을 쓰지 않는다. 키는 유지 - 목차·meta 구조가 고정이며
        # 과거 보고서와 형태가 갈리면 비교가 깨짐 (절대규칙 4)
        "llm": {
            "used": False, "provider": "null",
            "model": None, "prompt_version": None, "requested": False,
        },
    }


def _target_summary(requested: list[str], scanned: int) -> str:
    """개요 표기. 입력 원문 기준.

    포트 범위를 펼친 개별 포트를 나열하면 수백 건이 되어 읽을 수 없음.
    실제 몇 개 포트를 봤는지는 함께 밝혀 범위가 뭉개지지 않게 함
    """
    if not requested:
        return "대상 없음"
    head = requested[0] if len(requested) == 1 else \
        f"{requested[0]} 외 {len(requested) - 1}건"
    return f"{head} (포트 {scanned}개)" if scanned > len(requested) else head


def _top_risks(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    order = {s.value: i for i, s in enumerate(Severity)}
    ranked = sorted(
        findings,
        key=lambda f: (order.get(f["severity"], 99), -(f.get("cvss_score") or 0)),
    )
    return [
        {
            "finding_id": f["finding_id"], "name": f["name"],
            "severity": f["severity"], "reason": fallback.top_risk_reason(f),
        }
        for f in ranked[:TOP_RISK_LIMIT]
    ]


def _truncate(text: str | None, limit: int, note: str = "") -> str | None:
    if not text:
        return text
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n{TRUNCATION_MARKER}{note}"


def _finding_block(
    finding: dict[str, Any], *, include_evidence: bool
) -> dict[str, Any]:
    """모든 블록이 동일한 필드 구성을 가짐. 값이 없으면 대체 문구 (docs/04 A-5)"""
    block = {
        "finding_id": finding["finding_id"],
        "name": finding["name"],
        "severity": finding["severity"],
        "severity_label": SEVERITY_LABELS[Severity(finding["severity"])],
        # 탐지 심각도 환산값. 점검항목 중요도(guide_items)와 다른 값임
        "severity_guide": finding["severity_guide"],
        "vuln_type": finding["vuln_type"],
        "vuln_type_label": VULN_TYPE_LABELS[VulnType(finding["vuln_type"])],
        "cvss_score": finding.get("cvss_score"),
        "cve_ids": finding.get("cve_ids") or [],
        "cwe_ids": finding.get("cwe_ids") or [],
        "template_id": finding["template_id"],
        "template_source": finding["template_source"],
        "target": finding["target_raw"],
        "target_host": finding["target_host"],
        "description": finding.get("description"),
        "component_slug": finding.get("component_slug"),
        "guide_item_codes": finding.get("guide_item_codes") or [],
    }
    if include_evidence:
        block["evidence"] = {
            "request": _truncate(finding.get("ev_request"), EVIDENCE_LIMIT),
            "response": _truncate(finding.get("ev_response"), EVIDENCE_LIMIT),
            "curl_command": finding.get("ev_curl"),
            "included": True,
        }
    else:
        block["evidence"] = {
            "request": None, "response": None, "curl_command": None,
            "included": False,
        }
    return block


def _remediation(
    conn: sqlite3.Connection,
    scan_id: str,
    findings: list[dict[str, Any]],
    guide_items: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """유형 트랙. 가이드 원문을 그대로 인용하고 출처 페이지를 붙임 (절대규칙 9).

    정렬은 v_report_sections.priority_score 로 SQL 이 확정. LLM 미개입
    """
    sections = report_repo.report_sections(conn, scan_id)
    by_item = report_repo.findings_by_item(conn, scan_id)

    out: list[dict[str, Any]] = []
    for section in sections:
        item = guide_items.get(section["item_code"]) or {}
        original = item.get("remediation")
        out.append({
            "item_code": section["item_code"],
            "title": item.get("item_name") or section["item_code"],
            "finding_ids": by_item.get(section["item_code"], []),
            "priority_score": section["priority_score"],
            "source": "guide" if original else "template",
            "root_fix": {
                # 원문을 다듬지 않음. 없을 때만 대체 문구
                "summary": original or fallback.remediation_summary(
                    {"name": item.get("item_name")}
                ),
                "is_original": bool(original),
            },
            "temporary_fix": {"summary": fallback.temporary_fix()},
            "guide_item_code": section["item_code"] if original else None,
            "guide_citation": _citation(item),
            "guide_remediation_original": original,
            "narrative": None,
            "narrative_generated_by": fallback.GENERATED_BY_TEMPLATE,
        })
    return out


def _citation(item: dict[str, Any]) -> str | None:
    """출처는 항상 표기. 원문 인용 요건이자 대조 경로 (절대규칙 9)"""
    start, end = item.get("page_start"), item.get("page_end")
    if not start:
        return None
    pages = f"p.{start}" if not end or end == start else f"p.{start}~{end}"
    return f"KISA 상세가이드 {pages}"


def _patch_plan(conn: sqlite3.Connection, scan_id: str) -> list[dict[str, Any]]:
    """패치 트랙. fixed_version 결측은 빈칸이 아니라 대체 문구 (docs/04 A-6)"""
    out = []
    for row in report_repo.patch_plan(conn, scan_id):
        target = row["upgrade_to_at_least"] or None
        out.append({
            "component_type": row["component_type"],
            "slug": row["slug"],
            "installed_version": row["installed_version"],
            "upgrade_to_at_least": target,
            # 951행 중 332행이 결측이며 데이터 누락이 아님. 빈칸으로 두지 않음
            "upgrade_note": None if target else fallback.NO_UPGRADE_TARGET,
            "cve_ids": [c for c in (row["cve_ids"] or "").split(",") if c],
            "cve_count": row["cve_count"],
            "max_cvss": row["max_cvss"],
            "hosts": [row["target_host"]],
        })
    return out


def _guide_mapping(
    verdicts: list[guide_service.ItemVerdict],
    guide_items: dict[str, dict[str, Any]],
    guide_status: dict[str, Any],
) -> dict[str, Any]:
    items = []
    for verdict in verdicts:
        item = guide_items.get(verdict.item_code) or {}
        items.append({
            "item_code": verdict.item_code,
            "item_code_raw": item.get("item_code_raw"),
            "item_name": item.get("item_name"),
            "category": item.get("category"),
            # 점검항목 고유 중요도. 가이드 원문 값이며 탐지 환산값으로 덮지 않음
            "item_severity": item.get("severity_guide"),
            "verdict": verdict.verdict.value,
            "basis": verdict.basis,
            "finding_count": verdict.finding_count,
            "criteria_safe": item.get("criteria_safe"),
            "criteria_vuln": item.get("criteria_vuln"),
            "remediation": item.get("remediation"),
            "citation": _citation(item),
            "review_required": bool(item.get("review_required")),
        })
    return {
        "available": guide_status["imported"],
        "items": items,
        "summary": guide_service.summary(verdicts),
        # 고지 문장은 서버가 만든 하나만 사용. 사본을 두면 화면과 보고서가 갈라짐
        "coverage_notice": guide_status["coverage_notice"],
        "unavailable_note": None if guide_status["imported"]
        else fallback.GUIDE_UNAVAILABLE,
    }


def _unmapped(
    conn: sqlite3.Connection, scan_id: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """B-3. 없으면 Part A 와 Part B 의 건수가 맞지 않음"""
    mapped = report_repo.mapped_finding_ids(conn, scan_id)
    return [
        {
            "finding_id": f["finding_id"], "name": f["name"],
            "severity": f["severity"], "template_id": f["template_id"],
            "reason": "no_mapping",
        }
        for f in findings
        if f["finding_id"] not in mapped
    ]


def _appendix(conn: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    return {
        "severity_conversion_table": [
            {
                "range": f"{band.min} – {band.max}",
                "severity": band.severity.value,
                "severity_label": SEVERITY_LABELS[band.severity],
                "severity_guide": band.severity_guide.value,
            }
            for band in severity_mod.bands()
        ],
        "templates_used": report_repo.templates_used(conn, scan_id),
        "llm_generated_sections": [],
        "scope_note": (
            "본 진단은 원격 HTTP 스캔 기반이다. 계정 관리·파일 권한·서비스 데몬 설정 등"
            " 원격에서 접근할 수 없는 영역은 점검 범위에 포함되지 않는다."
        ),
    }


def dumps(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False)

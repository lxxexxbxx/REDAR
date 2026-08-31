"""scans · scan_targets · findings 조회. SQL 은 이 계층 전용."""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.domain import url as urlmod
from app.domain.enums import ScanStatus, Severity, VulnType

# 심각도는 문자열 정렬 시 순서가 뒤섞임. CASE 로 가중치 부여 (docs/05 §7)
_SEVERITY_RANK = (
    "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4"
    " WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END"
)
_SORT_COLUMNS = {
    "severity": _SEVERITY_RANK,
    "detected_at": "detected_at",
    "host": "target_host",
    "name": "name",
}


# ------------------------------------------------------------------ scans


def insert_scan(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    selection_mode: str,
    selection_detail: dict[str, Any] | None,
    collect_environment: bool,
    threads: int,
    timeout_sec: int,
    retries: int,
    rate_limit: int | None,
    targets: list[str],
    tool_version: str,
    nuclei_version: str | None,
    target_input: list[str] | None = None,
) -> None:
    conn.execute(
        "INSERT INTO scans (scan_id, status, selection_mode, selection_detail,"
        " collect_environment, opt_threads, opt_timeout_sec, opt_retries,"
        " opt_rate_limit, tool_version, nuclei_version, target_input)"
        " VALUES (?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_id,
            selection_mode,
            json.dumps(selection_detail, ensure_ascii=False)
            if selection_detail
            else None,
            int(collect_environment),
            threads,
            timeout_sec,
            retries,
            rate_limit,
            tool_version,
            nuclei_version,
            # 전개 전 원문. 화면·보고서 개요에서 '범위' 표기를 복원하는 유일한 근거
            json.dumps(target_input or targets, ensure_ascii=False),
        ),
    )
    for raw in targets:
        try:
            parts = urlmod.parse(raw)
            scheme, host, port = parts.scheme, parts.host, parts.port
        except ValueError:
            scheme, host, port = None, raw, None
        conn.execute(
            "INSERT INTO scan_targets (scan_id, raw, scheme, host, port)"
            " VALUES (?, ?, ?, ?, ?)",
            (scan_id, raw, scheme, host, port),
        )
    conn.commit()


def set_selection_basis(
    conn: sqlite3.Connection, scan_id: str, basis: dict[str, Any]
) -> None:
    """environment_driven 선별 근거. 보고서 부록의 '몇 개 중 몇 개' 근거값 (docs/02 §3.1)"""
    conn.execute(
        "UPDATE scans SET selection_basis = ? WHERE scan_id = ?",
        (json.dumps(basis, ensure_ascii=False), scan_id),
    )
    conn.commit()


def set_status(
    conn: sqlite3.Connection,
    scan_id: str,
    status: ScanStatus,
    *,
    error_code: str | None = None,
    error_message: str | None = None,
    templates_total: int | None = None,
    templates_done: int | None = None,
) -> None:
    fields = ["status = ?"]
    params: list[Any] = [status.value]

    if status is ScanStatus.RUNNING:
        fields.append("started_at = COALESCE(started_at, datetime('now','localtime'))")
    if status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED):
        fields.append("finished_at = datetime('now','localtime')")
    for column, value in (
        ("error_code", error_code),
        ("error_message", error_message),
        ("templates_total", templates_total),
        ("templates_done", templates_done),
    ):
        if value is not None:
            fields.append(f"{column} = ?")
            params.append(value)

    params.append(scan_id)
    conn.execute(f"UPDATE scans SET {', '.join(fields)} WHERE scan_id = ?", params)
    conn.commit()


def targets_of(conn: sqlite3.Connection, scan_id: str) -> list[str]:
    return [
        row["raw"]
        for row in conn.execute(
            "SELECT raw FROM scan_targets WHERE scan_id = ? ORDER BY scan_target_id",
            (scan_id,),
        )
    ]


def mark_reachable(
    conn: sqlite3.Connection, scan_id: str, reachable: list[str]
) -> None:
    """응답한 대상만 1, 나머지 0. 확인하지 않으면 NULL 그대로 둔다"""
    conn.execute(
        "UPDATE scan_targets SET reachable = 0 WHERE scan_id = ?", (scan_id,)
    )
    if reachable:
        marks = ", ".join("?" * len(reachable))
        conn.execute(
            f"UPDATE scan_targets SET reachable = 1"
            f" WHERE scan_id = ? AND raw IN ({marks})",
            (scan_id, *reachable),
        )
    conn.commit()


def target_probe(conn: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    """대상 응답 현황. 보고서 개요와 결과 화면이 같은 값을 쓴다"""
    rows = list(
        conn.execute(
            "SELECT raw, reachable FROM scan_targets WHERE scan_id = ?"
            " ORDER BY scan_target_id",
            (scan_id,),
        )
    )
    checked = [r for r in rows if r["reachable"] is not None]
    responded = [r["raw"] for r in checked if r["reachable"]]
    return {
        "requested": len(rows),
        # 확인하지 않은 스캔(이전 버전)은 요청 전부를 스캔한 것으로 본다
        "checked": len(checked),
        "responded": responded,
        "no_response": [r["raw"] for r in checked if not r["reachable"]],
    }


def _target_input(row: sqlite3.Row) -> list[str]:
    """입력 원문. 마이그레이션 이전 스캔은 컬럼이 비어 있어 전개 결과로 대체"""
    try:
        raw = row["target_input"]
    except (IndexError, KeyError):
        return []
    if not raw:
        return []
    try:
        return list(json.loads(raw))
    except (TypeError, ValueError):
        return []


def _scan_view(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    scan_id = row["scan_id"]
    counts = {s.value: 0 for s in Severity}
    for severity_row in conn.execute(
        "SELECT severity, COUNT(*) AS n FROM findings"
        " WHERE scan_id = ? AND status <> 'false_positive' GROUP BY severity",
        (scan_id,),
    ):
        counts[severity_row["severity"]] = severity_row["n"]
    has_report = bool(
        conn.execute(
            "SELECT 1 FROM reports WHERE scan_id = ? LIMIT 1", (scan_id,)
        ).fetchone()
    )
    return {
        "scan_id": scan_id,
        # 요청 대상. 포트 범위는 전개된 개별 포트가 들어감
        "targets": targets_of(conn, scan_id),
        # 사용자 입력 원문. 범위 표기를 화면·보고서 개요에서 복원하는 근거
        "target_input": _target_input(row),
        # 요청 / 응답 / 무응답. 실제로 무엇을 스캔했는지의 단일 출처
        "target_probe": target_probe(conn, scan_id),
        "status": row["status"],
        "created_at": row["created_at"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "duration_sec": _duration(conn, row),
        "finding_counts": counts,
        "has_report": has_report,
    }


def _duration(conn: sqlite3.Connection, row: sqlite3.Row) -> int | None:
    if not row["started_at"] or not row["finished_at"]:
        return None
    result = conn.execute(
        "SELECT CAST(strftime('%s', ?) - strftime('%s', ?) AS INTEGER)",
        (row["finished_at"], row["started_at"]),
    ).fetchone()
    return result[0]


def get_scan(conn: sqlite3.Connection, scan_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    view = _scan_view(conn, row)
    view["options"] = {
        "threads": row["opt_threads"],
        "timeout_sec": row["opt_timeout_sec"],
        "retries": row["opt_retries"],
        "rate_limit": row["opt_rate_limit"],
    }
    view["collect_environment"] = bool(row["collect_environment"])
    view["template_selection"] = {
        "mode": row["selection_mode"],
        **(json.loads(row["selection_detail"]) if row["selection_detail"] else {}),
    }
    # 선별 근거. environment_driven 이 아니면 None. 조건부 생략 없이 항상 키를 둠
    view["selection_basis"] = (
        json.loads(row["selection_basis"]) if row["selection_basis"] else None
    )
    view["templates_total"] = row["templates_total"]
    view["templates_done"] = row["templates_done"]
    # 재현성 기록. 보고서 meta 와 동일 값 (docs/00 §1.3)
    view["tool_version"] = row["tool_version"]
    view["nuclei_version"] = row["nuclei_version"]
    view["template_revision"] = row["template_revision"]
    profile = conn.execute(
        "SELECT profile_id FROM environment_profiles WHERE scan_id = ? LIMIT 1",
        (scan_id,),
    ).fetchone()
    view["environment_profile_id"] = profile["profile_id"] if profile else None
    view["error"] = (
        {"code": row["error_code"], "message": row["error_message"]}
        if row["error_code"]
        else None
    )
    return view


def list_scans(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    page: int = 1,
    size: int = 20,
) -> tuple[list[dict[str, Any]], int]:
    where, params = "", []
    if status:
        where = " WHERE status = ?"
        params.append(status)
    total = conn.execute(f"SELECT COUNT(*) FROM scans{where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM scans{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        [*params, size, (page - 1) * size],
    ).fetchall()
    return [_scan_view(conn, row) for row in rows], total


def delete_scan(conn: sqlite3.Connection, scan_id: str) -> bool:
    """findings·environment_profile·report 는 ON DELETE CASCADE 로 함께 삭제."""
    deleted = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,)).rowcount
    conn.commit()
    return bool(deleted)


def running_scan_id(conn: sqlite3.Connection) -> str | None:
    row = conn.execute(
        "SELECT scan_id FROM scans WHERE status IN ('queued','running') LIMIT 1"
    ).fetchone()
    return row["scan_id"] if row else None


# ---------------------------------------------------------------- findings


def _finding_view(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "finding_id": row["finding_id"],
        "scan_id": row["scan_id"],
        "fingerprint": row["fingerprint"],
        "source": row["source"],
        "template_id": row["template_id"],
        "template_source": row["template_source"],
        "matcher_name": row["matcher_name"],
        "target": {
            "raw": row["target_raw"],
            "scheme": row["target_scheme"],
            "host": row["target_host"],
            "port": row["target_port"],
            "path": row["target_path"],
        },
        "name": row["name"],
        "description": row["description"],
        "vuln_type": row["vuln_type"],
        "severity": row["severity"],
        "severity_guide": row["severity_guide"],
        "cve_ids": json.loads(row["cve_ids"]) if row["cve_ids"] else [],
        "cwe_ids": json.loads(row["cwe_ids"]) if row["cwe_ids"] else [],
        "cvss_score": row["cvss_score"],
        "cvss_vector": row["cvss_vector"],
        "evidence": {
            "request": row["ev_request"],
            "response": row["ev_response"],
            "extracted_values": json.loads(row["ev_extracted"])
            if row["ev_extracted"]
            else [],
            "curl_command": row["ev_curl"],
        },
        "status": row["status"],
        "status_note": row["status_note"],
        "detected_at": row["detected_at"],
    }


def _guide_refs(conn: sqlite3.Connection, finding_id: str) -> list[str]:
    """가이드 매핑은 M6. 미구현 상태에서는 빈 배열이 정상 (절대규칙 3)."""
    return [
        row["item_code"]
        for row in conn.execute(
            "SELECT item_code FROM finding_guide_refs WHERE finding_id = ?"
            " ORDER BY is_primary DESC, item_code",
            (finding_id,),
        )
    ]


def list_findings(
    conn: sqlite3.Connection,
    scan_id: str,
    *,
    severity: list[str] | None = None,
    vuln_type: list[str] | None = None,
    host: str | None = None,
    status: str | None = None,
    sort: str = "severity",
    order: str = "desc",
    page: int = 1,
    size: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    where = ["scan_id = ?"]
    params: list[Any] = [scan_id]
    if severity:
        where.append(f"severity IN ({', '.join('?' * len(severity))})")
        params += severity
    if vuln_type:
        where.append(f"vuln_type IN ({', '.join('?' * len(vuln_type))})")
        params += vuln_type
    if host:
        where.append("target_host = ?")
        params.append(host)
    if status:
        where.append("status = ?")
        params.append(status)

    clause = " AND ".join(where)
    total = conn.execute(
        f"SELECT COUNT(*) FROM findings WHERE {clause}", params
    ).fetchone()[0]

    sort_expr = _SORT_COLUMNS.get(sort, _SEVERITY_RANK)
    direction = "ASC" if order.lower() == "asc" else "DESC"
    rows = conn.execute(
        f"SELECT * FROM findings WHERE {clause}"
        f" ORDER BY {sort_expr} {direction}, detected_at DESC"
        " LIMIT ? OFFSET ?",
        [*params, size, (page - 1) * size],
    ).fetchall()

    items = []
    for row in rows:
        view = _finding_view(row)
        view["guide_refs"] = _guide_refs(conn, row["finding_id"])
        items.append(view)
    return items, total


def aggregate_findings(conn: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    """필터 적용 전 전체 기준. 오탐은 제외 (docs/00 §4).

    심각도 5종·유형 14종은 0 이어도 전부 반환. GUI 배지 레이아웃 고정용
    """
    by_severity = {s.value: 0 for s in Severity}
    by_vuln_type = {v.value: 0 for v in VulnType}
    by_host: dict[str, int] = {}

    for row in conn.execute(
        "SELECT severity, vuln_type, target_host, target_port, COUNT(*) AS n"
        " FROM findings WHERE scan_id = ? AND status <> 'false_positive'"
        " GROUP BY severity, vuln_type, target_host, target_port",
        (scan_id,),
    ):
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + row["n"]
        by_vuln_type[row["vuln_type"]] = by_vuln_type.get(row["vuln_type"], 0) + row["n"]
        label = row["target_host"]
        if row["target_port"]:
            label = f"{label}:{row['target_port']}"
        by_host[label] = by_host.get(label, 0) + row["n"]

    return {
        "by_severity": by_severity,
        "by_vuln_type": by_vuln_type,
        "by_host": by_host,
    }


def get_finding(conn: sqlite3.Connection, finding_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
    ).fetchone()
    if row is None:
        return None
    view = _finding_view(row)
    view["guide_refs"] = _guide_refs(conn, finding_id)
    # 매핑된 점검항목 전문. 본문 미탑재면 빈 배열이며 매핑(guide_refs)은 그대로 남음
    view["guide_items"] = [
        dict(item)
        for item in conn.execute(
            "SELECT g.*, r.is_primary, r.matched_by, r.confidence AS map_confidence"
            "  FROM finding_guide_refs r"
            "  JOIN guide_items g ON g.item_code = r.item_code"
            " WHERE r.finding_id = ?"
            # 대표 항목이 먼저. 보고서 Part B 본문 묶음과 같은 순서
            " ORDER BY r.is_primary DESC, g.item_code",
            (finding_id,),
        )
    ]
    return view


def update_finding_status(
    conn: sqlite3.Connection, finding_id: str, status: str, note: str | None
) -> bool:
    changed = conn.execute(
        "UPDATE findings SET status = ?, status_note = ? WHERE finding_id = ?",
        (status, note, finding_id),
    ).rowcount
    conn.commit()
    return bool(changed)

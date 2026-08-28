"""보고서 조회·저장. SQL 전용 (docs/02 §5).

집계·정렬을 SQL 로 고정하는 이유: 같은 스캔에 같은 순서가 나와야 재점검 비교가
성립한다. LLM 은 이 순서에 개입하지 않는다 (db/schema.sql §7)
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

_SEVERITY_ORDER = (
    "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3"
    " WHEN 'low' THEN 4 ELSE 5 END"
)


def findings_for_report(
    conn: sqlite3.Connection, scan_id: str, *, exclude_false_positives: bool = True
) -> list[dict[str, Any]]:
    """보고서 대상 탐지. 심각도 순 고정 정렬 (문자열 정렬은 뒤죽박죽이 된다)"""
    clause = " AND status <> 'false_positive'" if exclude_false_positives else ""
    rows = conn.execute(
        f"SELECT * FROM findings WHERE scan_id = ?{clause}"
        f" ORDER BY {_SEVERITY_ORDER}, name, finding_id",
        (scan_id,),
    ).fetchall()
    refs = _refs_by_finding(conn, scan_id)
    out = []
    for row in rows:
        item = dict(row)
        item["cve_ids"] = json.loads(row["cve_ids"] or "[]")
        item["cwe_ids"] = json.loads(row["cwe_ids"] or "[]")
        item["ev_extracted"] = json.loads(row["ev_extracted"] or "[]")
        item["guide_item_codes"] = refs.get(row["finding_id"], [])
        out.append(item)
    return out


def false_positives(conn: sqlite3.Connection, scan_id: str) -> list[dict[str, Any]]:
    """A-7. 집계에서 제외되었음을 보고서에 남긴다"""
    return [
        dict(row)
        for row in conn.execute(
            f"SELECT finding_id, name, severity, status_note FROM findings"
            f" WHERE scan_id = ? AND status = 'false_positive'"
            f" ORDER BY {_SEVERITY_ORDER}, finding_id",
            (scan_id,),
        )
    ]


def _refs_by_finding(conn: sqlite3.Connection, scan_id: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for row in conn.execute(
        "SELECT r.finding_id, r.item_code FROM finding_guide_refs r"
        " JOIN findings f ON f.finding_id = r.finding_id"
        " WHERE f.scan_id = ? ORDER BY r.is_primary DESC, r.item_code",
        (scan_id,),
    ):
        out.setdefault(row["finding_id"], []).append(row["item_code"])
    return out


def mapped_finding_ids(conn: sqlite3.Connection, scan_id: str) -> set[str]:
    return {
        row["finding_id"]
        for row in conn.execute(
            "SELECT DISTINCT r.finding_id FROM finding_guide_refs r"
            " JOIN findings f ON f.finding_id = r.finding_id WHERE f.scan_id = ?",
            (scan_id,),
        )
    }


def findings_by_item(conn: sqlite3.Connection, scan_id: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for row in conn.execute(
        "SELECT r.item_code, r.finding_id FROM finding_guide_refs r"
        " JOIN findings f ON f.finding_id = r.finding_id"
        " WHERE f.scan_id = ? AND r.is_primary = 1 AND f.status <> 'false_positive'"
        " ORDER BY r.item_code, r.finding_id",
        (scan_id,),
    ):
        out.setdefault(row["item_code"], []).append(row["finding_id"])
    return out


def report_sections(conn: sqlite3.Connection, scan_id: str) -> list[dict[str, Any]]:
    """조치 우선순위. priority_score 는 SQL 이 확정한다 (docs/04 A-6)"""
    return [
        dict(row)
        for row in conn.execute(
            "SELECT * FROM v_report_sections WHERE scan_id = ?"
            " ORDER BY priority_score DESC, item_code",
            (scan_id,),
        )
    ]


def patch_plan(conn: sqlite3.Connection, scan_id: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            "SELECT * FROM v_patch_plan WHERE scan_id = ?"
            " ORDER BY COALESCE(max_cvss, 0) DESC, slug",
            (scan_id,),
        )
    ]


def guide_items_for_scan(
    conn: sqlite3.Connection, scan_id: str
) -> dict[str, dict[str, Any]]:
    """매핑 대상 점검항목 본문. 미탑재면 빈 dict (절대규칙 3).

    review_required: confidence=low 이고 미검수인 매핑 (docs/04 B-2)
    """
    review = {
        row["item_code"]
        for row in conn.execute(
            "SELECT DISTINCT item_code FROM guide_mappings"
            " WHERE confidence = 'low' AND reviewed = 0"
        )
    }
    del scan_id                       # 본문은 스캔과 무관. 시그니처 일관성 유지용
    out: dict[str, dict[str, Any]] = {}
    for row in conn.execute("SELECT * FROM guide_items ORDER BY item_code"):
        item = dict(row)
        item["review_required"] = row["item_code"] in review
        out[row["item_code"]] = item
    return out


def templates_used(conn: sqlite3.Connection, scan_id: str) -> list[dict[str, Any]]:
    """실행 템플릿. scan_templates 가 비면 탐지된 템플릿으로 대체한다"""
    rows = conn.execute(
        "SELECT template_id, source FROM scan_templates WHERE scan_id = ?"
        " ORDER BY template_id",
        (scan_id,),
    ).fetchall()
    if rows:
        return [dict(row) for row in rows]
    return [
        {"template_id": row["template_id"], "source": row["template_source"]}
        for row in conn.execute(
            "SELECT DISTINCT template_id, template_source FROM findings"
            " WHERE scan_id = ? ORDER BY template_id",
            (scan_id,),
        )
    ]


# ────────────────────────────────────────────── reports 테이블

def insert(
    conn: sqlite3.Connection,
    *,
    report_id: str,
    scan_id: str,
    options: dict[str, Any],
    guide_status: dict[str, Any],
) -> None:
    conn.execute(
        "INSERT INTO reports (report_id, scan_id, status, opt_use_llm,"
        " opt_include_guide_mapping, opt_include_evidence,"
        " opt_exclude_false_positives, opt_include_guide_cases,"
        " guide_db_available, guide_db_version, guide_items_total,"
        " guide_items_covered)"
        " VALUES (?, ?, 'generating', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            report_id, scan_id,
            int(options["use_llm"]), int(options["include_guide_mapping"]),
            int(options["include_evidence"]), int(options["exclude_false_positives"]),
            int(options["include_guide_cases"]),
            int(guide_status["imported"]), guide_status["version"],
            guide_status["item_count"], guide_status["items_covered"],
        ),
    )
    conn.commit()


def finish(
    conn: sqlite3.Connection,
    report_id: str,
    *,
    report_json: str,
    llm_used: bool = False,
    llm_provider: str | None = None,
    llm_model: str | None = None,
    llm_prompt_version: str | None = None,
    llm_fallback_count: int = 0,
) -> None:
    conn.execute(
        "UPDATE reports SET status = 'completed', report_json = ?, llm_used = ?,"
        " llm_provider = ?, llm_model = ?, llm_prompt_version = ?,"
        " llm_fallback_count = ? WHERE report_id = ?",
        (report_json, int(llm_used), llm_provider, llm_model, llm_prompt_version,
         llm_fallback_count, report_id),
    )
    conn.commit()


def fail(conn: sqlite3.Connection, report_id: str, message: str) -> None:
    conn.execute(
        "UPDATE reports SET status = 'failed', error_message = ?"
        " WHERE report_id = ?",
        (message[:500], report_id),
    )
    conn.commit()


def get(conn: sqlite3.Connection, report_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM reports WHERE report_id = ?", (report_id,)
    ).fetchone()
    if row is None:
        return None
    view = dict(row)
    view["report"] = json.loads(row["report_json"]) if row["report_json"] else None
    view["files"] = files(conn, report_id)
    return view


def listing(
    conn: sqlite3.Connection, *, scan_id: str | None = None,
    page: int = 1, size: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    clause = " WHERE scan_id = ?" if scan_id else ""
    params: list[Any] = [scan_id] if scan_id else []
    total = conn.execute(
        f"SELECT COUNT(*) FROM reports{clause}", params
    ).fetchone()[0]
    rows = conn.execute(
        f"SELECT report_id, scan_id, status, generated_at, guide_db_available,"
        f" llm_used FROM reports{clause}"
        f" ORDER BY generated_at DESC, report_id DESC LIMIT ? OFFSET ?",
        [*params, size, max(page - 1, 0) * size],
    ).fetchall()
    return [dict(row) for row in rows], total


def delete(conn: sqlite3.Connection, report_id: str) -> bool:
    cur = conn.execute("DELETE FROM reports WHERE report_id = ?", (report_id,))
    conn.commit()
    return cur.rowcount > 0


def add_file(
    conn: sqlite3.Connection,
    report_id: str,
    *,
    fmt: str,
    file_path: str,
    size_bytes: int,
    sha256: str,
) -> None:
    conn.execute(
        "INSERT INTO report_files (report_id, format, file_path, size_bytes, sha256)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT (report_id, format) DO UPDATE SET"
        " file_path = excluded.file_path, size_bytes = excluded.size_bytes,"
        " sha256 = excluded.sha256, created_at = datetime('now','localtime')",
        (report_id, fmt, file_path, size_bytes, sha256),
    )
    conn.commit()


def files(conn: sqlite3.Connection, report_id: str) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            "SELECT format, file_path, size_bytes, sha256, created_at"
            " FROM report_files WHERE report_id = ? ORDER BY format",
            (report_id,),
        )
    ]

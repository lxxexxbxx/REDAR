"""가이드 데이터 조회 · 임포트.

본문(guide_items)은 미탑재가 정상 상태. 매핑 테이블은 번들이라 항상 존재 (절대규칙 3)
본문·이미지는 저작권 대상이라 저장소에 없고 사용자가 임포트 (절대규칙 8)
"""
from __future__ import annotations

import sqlite3
from typing import Any

from app.domain.models import format_coverage_notice


def status(conn: sqlite3.Connection) -> dict[str, Any]:
    coverage = conn.execute("SELECT * FROM v_guide_coverage").fetchone()
    row = conn.execute(
        "SELECT guide_version, MAX(imported_at) AS imported_at FROM guide_items"
    ).fetchone()
    item_count = coverage["items_total"]
    return {
        "imported": item_count > 0,
        "version": row["guide_version"] if item_count else None,
        "item_count": item_count,
        "imported_at": row["imported_at"] if item_count else None,
        "mapping_count": conn.execute(
            "SELECT COUNT(*) FROM guide_mappings"
        ).fetchone()[0],
        # 자동 점검 가능 항목 수. 커버리지 고지의 근거값 (절대규칙 10)
        "items_covered": coverage["items_covered"],
        # 고지 문장을 서버가 내려줌. GUI 와 보고서가 같은 문장을 쓰도록 단일화
        "coverage_notice": format_coverage_notice(
            item_count, coverage["items_covered"]
        ),
    }


# FTS 는 본문과 동기화하는 트리거가 없다. 임포트마다 이 함수로 다시 채움
# 누락 시 에러 없이 유사항목 검색만 0건이 되어 발견이 늦음
_FTS_COLUMNS = (
    "item_code", "item_name", "check_content", "security_threat",
    "remediation", "case_text",
)


def clear_images(conn: sqlite3.Connection, item_codes: list[str]) -> int:
    """재임포트 시 이미지 중복 방지. guide_item_images 에 UNIQUE 제약이 없어 필요"""
    if not item_codes:
        return 0
    marks = ", ".join("?" * len(item_codes))
    cur = conn.execute(
        f"DELETE FROM guide_item_images WHERE item_code IN ({marks})", item_codes
    )
    return cur.rowcount


def replace_images(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """이미지 전체 교체. guide_item_images 에 UNIQUE 가 없어 재임포트 시 중복됨"""
    conn.execute("DELETE FROM guide_item_images")
    if not rows:
        return 0
    columns = [c["name"] for c in conn.execute("PRAGMA table_info(guide_item_images)")
               if c["name"] != "image_id"]
    usable = [c for c in columns if c in rows[0]]
    conn.executemany(
        f"INSERT INTO guide_item_images ({', '.join(usable)})"
        f" VALUES ({', '.join('?' * len(usable))})",
        [[row.get(c) or None for c in usable] for row in rows],
    )
    return len(rows)


def rebuild_fts(conn: sqlite3.Connection) -> int:
    """전문검색 인덱스 재구축. 본문 적재 후 반드시 호출"""
    conn.execute("DELETE FROM guide_items_fts")
    columns = ", ".join(_FTS_COLUMNS)
    conn.execute(
        f"INSERT INTO guide_items_fts ({columns}) SELECT {columns} FROM guide_items"
    )
    return conn.execute("SELECT COUNT(*) FROM guide_items_fts").fetchone()[0]


def versions(conn: sqlite3.Connection) -> list[str]:
    return [
        r["guide_version"]
        for r in conn.execute(
            "SELECT DISTINCT guide_version FROM guide_items ORDER BY guide_version"
        )
    ]


def orphan_image_codes(conn: sqlite3.Connection) -> list[str]:
    """본문 없는 이미지. FK 로 막히지만 원인을 알려주기 위해 먼저 확인"""
    return [
        r["item_code"]
        for r in conn.execute(
            "SELECT DISTINCT i.item_code FROM guide_item_images i"
            " LEFT JOIN guide_items g ON g.item_code = i.item_code"
            " WHERE g.item_code IS NULL"
        )
    ]


# ────────────────────────────────────────────── 매핑 (M6)

def load_mappings(conn: sqlite3.Connection) -> dict:
    """match_type -> match_value -> 규칙 목록. 스캔마다 한 번만 읽음"""
    out: dict = {}
    for row in conn.execute(
        "SELECT match_type, match_value, item_code, confidence, mapping_basis,"
        " reviewed FROM guide_mappings ORDER BY match_type, match_value, item_code"
    ):
        table = out.setdefault(row["match_type"], {})
        table.setdefault(row["match_value"], []).append({
            "item_code": row["item_code"],
            "confidence": row["confidence"],
            "mapping_basis": row["mapping_basis"],
            # confidence=low 이고 미검수면 보고서에 '검토 필요' 표기 (docs/03 §3.5)
            "needs_review": row["confidence"] == "low" and not row["reviewed"],
        })
    return out


def mapped_item_codes(conn: sqlite3.Connection) -> list[str]:
    return [
        r["item_code"]
        for r in conn.execute(
            "SELECT DISTINCT item_code FROM guide_mappings ORDER BY item_code"
        )
    ]


def mappable_findings(conn: sqlite3.Connection, scan_id: str) -> list[dict]:
    """자산 식별 템플릿(is_detection=1)은 취약점이 아니므로 제외 (docs/05 자주 하는 실수).

    오탐 표시된 항목도 제외 - 집계에서 빠지므로 매핑도 남기지 않음
    """
    rows = conn.execute(
        "SELECT f.finding_id, f.template_id, f.cve_ids, f.cwe_ids, f.vuln_type,"
        "       f.component_slug"
        "  FROM findings f"
        "  LEFT JOIN templates t ON t.template_id = f.template_id"
        " WHERE f.scan_id = ?"
        "   AND f.status <> 'false_positive'"
        "   AND COALESCE(t.is_detection, 0) = 0"
        " ORDER BY f.finding_id",
        (scan_id,),
    )
    return [dict(row) for row in rows]


def detection_finding_count(conn: sqlite3.Connection, scan_id: str) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM findings f"
        " JOIN templates t ON t.template_id = f.template_id"
        " WHERE f.scan_id = ? AND t.is_detection = 1",
        (scan_id,),
    ).fetchone()[0]


def replace_refs(
    conn: sqlite3.Connection, scan_id: str, rows: list[tuple]
) -> None:
    """스캔 범위의 매핑을 교체. 재매핑이 중복 행을 만들지 않게 한다"""
    conn.execute(
        "DELETE FROM finding_guide_refs WHERE finding_id IN"
        " (SELECT finding_id FROM findings WHERE scan_id = ?)",
        (scan_id,),
    )
    conn.executemany(
        "INSERT INTO finding_guide_refs"
        " (finding_id, item_code, confidence, is_primary, matched_by)"
        " VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()


def ref_counts(conn: sqlite3.Connection, scan_id: str) -> dict[str, int]:
    return {
        r["item_code"]: r["n"]
        for r in conn.execute(
            "SELECT r.item_code, COUNT(*) AS n FROM finding_guide_refs r"
            " JOIN findings f ON f.finding_id = r.finding_id"
            " WHERE f.scan_id = ? GROUP BY r.item_code",
            (scan_id,),
        )
    }


def items(
    conn: sqlite3.Connection,
    *,
    codes: list[str] | None = None,
    category: str | None = None,
    query: str | None = None,
    page: int = 1,
    size: int = 50,
) -> tuple[list[dict], int]:
    """점검항목 조회. 본문 미탑재면 빈 목록 (절대규칙 3)"""
    where: list[str] = []
    params: list = []
    if codes:
        where.append(f"item_code IN ({', '.join('?' * len(codes))})")
        params += codes
    if category:
        where.append("category = ?")
        params.append(category)
    if query:
        where.append("(item_code LIKE ? OR item_name LIKE ?)")
        params += [f"%{query}%", f"%{query}%"]
    clause = f" WHERE {' AND '.join(where)}" if where else ""

    total = conn.execute(
        f"SELECT COUNT(*) FROM guide_items{clause}", params
    ).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM guide_items{clause} ORDER BY item_code LIMIT ? OFFSET ?",
        [*params, size, max(page - 1, 0) * size],
    ).fetchall()
    return [dict(row) for row in rows], total


def replace_items(conn: sqlite3.Connection, rows: list[dict]) -> int:
    """본문 전체 삭제 후 재적재 (docs/03 §2.3).

    finding_guide_refs 는 건드리지 않음 - 별도 층이며 본문 없이도 유지됨
    """
    if not rows:
        return 0
    columns = [c["name"] for c in conn.execute("PRAGMA table_info(guide_items)")
               if c["name"] != "imported_at"]
    usable = [c for c in columns if c in rows[0]]
    conn.execute("DELETE FROM guide_items")
    conn.executemany(
        f"INSERT INTO guide_items ({', '.join(usable)})"
        f" VALUES ({', '.join('?' * len(usable))})",
        [[row.get(c) or None for c in usable] for row in rows],
    )
    return len(rows)

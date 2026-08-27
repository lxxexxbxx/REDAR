"""가이드 데이터 조회.

본문(guide_items)은 미탑재가 정상 상태. 매핑 테이블은 번들이라 항상 존재 (절대규칙 3)
"""
from __future__ import annotations

import sqlite3
from typing import Any


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
    }

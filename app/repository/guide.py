"""가이드 데이터 조회 · 임포트.

본문(guide_items)은 미탑재가 정상 상태. 매핑 테이블은 번들이라 항상 존재 (절대규칙 3)
본문·이미지는 저작권 대상이라 저장소에 없고 사용자가 임포트한다 (절대규칙 8)
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
        # 고지 문장을 서버가 내려준다. GUI 와 보고서가 같은 문장을 쓰도록 단일화
        "coverage_notice": format_coverage_notice(
            item_count, coverage["items_covered"]
        ),
    }


# FTS 는 본문과 동기화하는 트리거가 없다. 임포트마다 이 함수로 다시 채운다.
# 누락 시 에러 없이 유사항목 검색만 0건이 되어 발견이 늦다
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

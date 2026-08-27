"""번들 매핑 테이블 조회."""
from __future__ import annotations

import sqlite3

from app.domain.enums import VulnType
from app.domain.vuln_type import TypeRule


def load_vuln_type_rules(conn: sqlite3.Connection) -> list[TypeRule]:
    """정의 순서(priority -> rule_id) 반환. rule_id 순 = CSV 행 순 = 동순위 타이브레이커."""
    rows = conn.execute(
        "SELECT match_type, match_value, vuln_type, priority"
        " FROM vuln_type_rules ORDER BY priority, rule_id"
    )
    return [
        TypeRule(
            match_type=r["match_type"],
            match_value=r["match_value"],
            vuln_type=VulnType(r["vuln_type"]),
            priority=r["priority"],
        )
        for r in rows
    ]

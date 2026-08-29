"""환경 조사 결과 저장·조회. SQL 전용 (docs/02 §3.2).

주요 스택은 컬럼, 구성요소·노출은 행. 개수가 가변인 것만 테이블로 분리
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

_STACK_FIELDS = ("web_server", "language", "application")

_INSERT_PROFILE = """
INSERT INTO environment_profiles (
    profile_id, scan_id, target_host,
    web_server_product, web_server_version, web_server_confidence,
    language_product, language_version, language_confidence,
    application_product, application_version, application_confidence,
    collectors_run, collectors_failed
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (scan_id, target_host) DO UPDATE SET
    web_server_product = excluded.web_server_product,
    web_server_version = excluded.web_server_version,
    web_server_confidence = excluded.web_server_confidence,
    language_product = excluded.language_product,
    language_version = excluded.language_version,
    language_confidence = excluded.language_confidence,
    application_product = excluded.application_product,
    application_version = excluded.application_version,
    application_confidence = excluded.application_confidence,
    collectors_run = excluded.collectors_run,
    collectors_failed = excluded.collectors_failed,
    collected_at = datetime('now','localtime')
"""


def save_profile(
    conn: sqlite3.Connection,
    *,
    profile_id: str,
    scan_id: str,
    target_host: str,
    stack: dict[str, dict[str, Any]],
    components: list[dict[str, Any]],
    exposures: list[dict[str, Any]],
    collectors_run: list[str],
    collectors_failed: list[str],
) -> str:
    """프로필 1건 저장. 재수집 시 같은 (scan_id, target_host) 를 갱신"""
    values: list[Any] = [profile_id, scan_id, target_host]
    for field in _STACK_FIELDS:
        item = stack.get(field) or {}
        values += [item.get("product"), item.get("version"), item.get("confidence")]
    values += [
        json.dumps(collectors_run, ensure_ascii=False),
        json.dumps(collectors_failed, ensure_ascii=False),
    ]
    conn.execute(_INSERT_PROFILE, values)

    row = conn.execute(
        "SELECT profile_id FROM environment_profiles"
        " WHERE scan_id = ? AND target_host = ?",
        (scan_id, target_host),
    ).fetchone()
    stored_id = row["profile_id"]

    # 재수집이면 이전 행을 지우고 다시 넣음. UNIQUE 가 있어도 사라진 항목이 남음
    conn.execute("DELETE FROM env_components WHERE profile_id = ?", (stored_id,))
    conn.execute("DELETE FROM env_exposures WHERE profile_id = ?", (stored_id,))

    conn.executemany(
        "INSERT INTO env_components"
        " (profile_id, type, slug, name, version, active, confidence, evidence)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                stored_id, c["type"], c["slug"], c.get("name"), c.get("version"),
                None if c.get("active") is None else int(c["active"]),
                c.get("confidence", "medium"), c.get("evidence"),
            )
            for c in components
        ],
    )
    conn.executemany(
        "INSERT INTO env_exposures (profile_id, key, value, path, evidence)"
        " VALUES (?, ?, ?, ?, ?)",
        [
            (stored_id, e["key"], int(e["value"]), e.get("path"), e.get("evidence"))
            for e in exposures
        ],
    )
    conn.commit()
    return stored_id


def profiles(conn: sqlite3.Connection, scan_id: str) -> list[dict[str, Any]]:
    """§1.2 EnvironmentProfile 형태로 반환. 대상 여러 개면 여러 건"""
    rows = conn.execute(
        "SELECT * FROM environment_profiles WHERE scan_id = ? ORDER BY target_host",
        (scan_id,),
    ).fetchall()
    return [_view(conn, row) for row in rows]


def _view(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    profile_id = row["profile_id"]
    return {
        "profile_id": profile_id,
        "scan_id": row["scan_id"],
        "target_host": row["target_host"],
        "collected_at": row["collected_at"],
        **{
            field: {
                "product": row[f"{field}_product"],
                "version": row[f"{field}_version"],
                "confidence": row[f"{field}_confidence"] or "low",
            }
            for field in _STACK_FIELDS
        },
        "components": [
            {
                "type": c["type"], "slug": c["slug"], "name": c["name"],
                "version": c["version"],
                "active": None if c["active"] is None else bool(c["active"]),
                "confidence": c["confidence"], "evidence": c["evidence"],
            }
            for c in conn.execute(
                "SELECT * FROM env_components WHERE profile_id = ?"
                " ORDER BY type, slug", (profile_id,)
            )
        ],
        "exposures": [
            {
                "key": e["key"], "value": bool(e["value"]),
                "path": e["path"], "evidence": e["evidence"],
            }
            for e in conn.execute(
                "SELECT * FROM env_exposures WHERE profile_id = ? ORDER BY key",
                (profile_id,),
            )
        ],
        "collectors_run": json.loads(row["collectors_run"] or "[]"),
        "collectors_failed": json.loads(row["collectors_failed"] or "[]"),
    }


def advisory_templates(
    conn: sqlite3.Connection, slugs: list[str]
) -> dict[str, list[str]]:
    """구성요소 슬러그 -> 연결된 템플릿 id. environment_driven 선별 입력"""
    if not slugs:
        return {}
    marks = ", ".join("?" * len(slugs))
    out: dict[str, list[str]] = {}
    for row in conn.execute(
        f"SELECT slug, template_id FROM component_advisories"
        f" WHERE slug IN ({marks}) AND template_id IS NOT NULL"
        f" ORDER BY slug, template_id",
        slugs,
    ):
        out.setdefault(row["slug"], []).append(row["template_id"])
    return out


def local_template_count(conn: sqlite3.Connection) -> int:
    """로컬 템플릿 인벤토리 크기. selection_basis.total_available 의 분모.

    M5 의 템플릿 관리가 채움. 그전에는 0 이며 선별 근거에 0 으로 남음
    """
    return conn.execute("SELECT COUNT(*) FROM templates").fetchone()[0]


def templates_for_ids(
    conn: sqlite3.Connection, template_ids: list[str]
) -> list[str]:
    """인벤토리에 실제로 존재하는 템플릿만 남김. 없으면 빈 목록"""
    if not template_ids:
        return []
    marks = ", ".join("?" * len(template_ids))
    return [
        r["template_id"]
        for r in conn.execute(
            f"SELECT template_id FROM templates WHERE template_id IN ({marks})"
            f" ORDER BY template_id",
            template_ids,
        )
    ]

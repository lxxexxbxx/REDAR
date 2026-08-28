"""템플릿 인벤토리. SQL 전용 (docs/02 §4).

templates 테이블은 로컬에 있는 템플릿의 색인이다. YAML 본문은 파일에 있고
DB 에는 메타데이터만 둔다 - 본문을 DB 에 넣으면 nuclei 가 읽을 파일이 따로 필요해진다
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

_COLUMNS = (
    "template_id", "source", "file_path", "name", "description", "severity",
    "vuln_type", "cve_ids", "cwe_ids", "tags", "cvss_score", "cvss_vector",
    "fixed_version", "is_detection", "component_slugs", "form_json", "yaml_hash",
)

_UPSERT = f"""
INSERT INTO templates ({', '.join(_COLUMNS)})
VALUES ({', '.join('?' * len(_COLUMNS))})
ON CONFLICT (template_id) DO UPDATE SET
    {', '.join(f'{c} = excluded.{c}' for c in _COLUMNS if c != 'template_id')},
    updated_at = datetime('now','localtime')
"""


# NOT NULL 컬럼의 기본값. 부분 행을 넣어도 스키마 기본값과 같은 결과가 되게 한다
_DEFAULTS = {"is_detection": 0}


def _values(row: dict[str, Any]) -> list[Any]:
    return [
        _encode(row.get(column) if row.get(column) is not None
                else _DEFAULTS.get(column))
        for column in _COLUMNS
    ]


def upsert(conn: sqlite3.Connection, row: dict[str, Any]) -> None:
    conn.execute(_UPSERT, _values(row))
    conn.commit()


def upsert_many(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> int:
    conn.executemany(_UPSERT, [_values(row) for row in rows])
    conn.commit()
    return len(rows)


def _encode(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return int(value)
    return value


def get(conn: sqlite3.Connection, template_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM templates WHERE template_id = ?", (template_id,)
    ).fetchone()
    return _view(row) if row else None


def delete(conn: sqlite3.Connection, template_id: str) -> bool:
    cur = conn.execute("DELETE FROM templates WHERE template_id = ?", (template_id,))
    conn.commit()
    return cur.rowcount > 0


def search(
    conn: sqlite3.Connection,
    *,
    source: str | None = None,
    severity: list[str] | None = None,
    tags: list[str] | None = None,
    query: str | None = None,
    page: int = 1,
    size: int = 50,
) -> tuple[list[dict[str, Any]], int]:
    where: list[str] = []
    params: list[Any] = []
    if source:
        where.append("source = ?")
        params.append(source)
    if severity:
        where.append(f"severity IN ({', '.join('?' * len(severity))})")
        params += severity
    if tags:
        # tags 는 JSON 배열 문자열. 태그 1개라도 포함되면 매칭
        where.append("(" + " OR ".join("tags LIKE ?" for _ in tags) + ")")
        params += [f'%"{tag}"%' for tag in tags]
    if query:
        where.append("(template_id LIKE ? OR name LIKE ?)")
        params += [f"%{query}%", f"%{query}%"]

    clause = f" WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(
        f"SELECT COUNT(*) FROM templates{clause}", params
    ).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM templates{clause}"
        # 심각도 문자열 정렬은 뒤죽박죽이 된다. CASE 로 고정 (docs/05 자주 하는 실수)
        " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2"
        "   WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END,"
        " template_id LIMIT ? OFFSET ?",
        [*params, size, max(page - 1, 0) * size],
    ).fetchall()
    return [_view(row) for row in rows], total


def revision(conn: sqlite3.Connection) -> str | None:
    """공식 템플릿 색인 시각. 재현성 기록용 (scans.template_revision)"""
    row = conn.execute(
        "SELECT MAX(updated_at) AS at FROM templates WHERE source = 'official'"
    ).fetchone()
    return row["at"]


def _view(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "template_id": row["template_id"],
        "source": row["source"],
        "file_path": row["file_path"],
        "name": row["name"],
        "description": row["description"],
        "severity": row["severity"],
        "vuln_type": row["vuln_type"],
        "cve_ids": json.loads(row["cve_ids"] or "[]"),
        "cwe_ids": json.loads(row["cwe_ids"] or "[]"),
        "tags": json.loads(row["tags"] or "[]"),
        "cvss_score": row["cvss_score"],
        "fixed_version": row["fixed_version"],
        "is_detection": bool(row["is_detection"]),
        "updated_at": row["updated_at"],
    }

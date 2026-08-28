"""settings 테이블 조회·갱신.

key-value 구조라 항목 추가에 마이그레이션 불필요 (db/schema.sql §0).
값은 JSON 또는 스칼라 문자열
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

# 외부 통신 지점 3개. 이 목록이 전부 (절대규칙 5, docs/01 §7.1)
#
# 키 목록만 코드에 둔다. CSV 로 내리면 네 번째 지점을 데이터로 추가할 수 있게 되어
# 통제가 무너진다. URL 기본값은 데이터이므로 data/settings_defaults.csv 의
# ext_<key>_url 이 출처
EXTERNAL_ENDPOINT_KEYS = ("template_sync", "llm_api", "cve_lookup")

_TRUE = {"true", "1", "yes", "on"}


def get_all(conn: sqlite3.Connection) -> dict[str, str]:
    return {
        row["key"]: row["value"]
        for row in conn.execute("SELECT key, value FROM settings")
    }


def put_many(conn: sqlite3.Connection, values: dict[str, Any]) -> None:
    conn.executemany(
        "INSERT INTO settings (key, value) VALUES (?, ?)"
        " ON CONFLICT (key) DO UPDATE SET"
        " value = excluded.value, updated_at = datetime('now','localtime')",
        [(key, _dump(value)) for key, value in values.items()],
    )
    conn.commit()


def _dump(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def as_bool(raw: str | None, default: bool = False) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE


def as_int(raw: str | None, default: int) -> int:
    try:
        return int(str(raw))
    except (TypeError, ValueError):
        return default


def as_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return [str(v) for v in parsed] if isinstance(parsed, list) else []


def target_allowlist(conn: sqlite3.Connection) -> list[str]:
    """스캔 진입점에서 매번 조회. 캐시하지 않음.

    설정 변경이 즉시 반영되어야 하고, 캐시가 낡으면 차단 대상이 통과
    """
    row = conn.execute(
        "SELECT value FROM settings WHERE key = 'target_allowlist'"
    ).fetchone()
    return as_list(row["value"] if row else None)


def offline_mode(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT value FROM settings WHERE key = 'offline_mode'"
    ).fetchone()
    return as_bool(row["value"] if row else None, default=True)

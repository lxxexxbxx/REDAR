"""SQLite 커넥션 관리. SQL 은 repository 계층 전용."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.config import settings


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or settings.DB_PATH)
    conn.row_factory = sqlite3.Row
    # foreign_keys 기본값 OFF, 커넥션마다 설정 필요. 누락 시 FK 위반 통과 (docs/02 §5.1)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")     # 스캔 중 쓰기 + GUI 읽기 병행
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 5000")    # 쓰기 경합 시 대기
    return conn


@contextmanager
def session(db_path: Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(db_path)
    try:
        yield conn
    finally:
        conn.close()

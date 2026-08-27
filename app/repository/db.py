"""SQLite 커넥션 관리. SQL 은 이 계층에만 둔다."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from app.config import settings


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or settings.DB_PATH)
    conn.row_factory = sqlite3.Row
    # foreign_keys 는 SQLite 기본값이 OFF 이고 커넥션마다 설정해야 한다.
    # 빠뜨리면 FK 위반이 조용히 통과한다 (docs/02 §5.1).
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")     # 스캔 중 쓰기 + GUI 읽기 병행
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 5000")    # 쓰기 경합 시 즉시 잠김 대신 대기
    return conn


@contextmanager
def session(db_path: Path | None = None) -> Iterator[sqlite3.Connection]:
    conn = connect(db_path)
    try:
        yield conn
    finally:
        conn.close()

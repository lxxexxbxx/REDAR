"""FastAPI 앱. 루프백 전용 (docs/00 §0.1)."""
from __future__ import annotations

import sqlite3

from fastapi import FastAPI

from app.adapters import nuclei
from app.repository.db import session

API_PREFIX = "/api/v1"

app = FastAPI(title="REDAR", version="0.3.0", docs_url=f"{API_PREFIX}/docs")


@app.get(f"{API_PREFIX}/health")
def health() -> dict[str, str | None]:
    try:
        with session() as conn:
            conn.execute("SELECT 1 FROM schema_version LIMIT 1").fetchone()
        db = "connected"
    except sqlite3.Error:
        # DB 가 없어도 200 으로 응답한다. GUI 가 init-db 안내를 띄우려면
        # 헬스체크 자체는 성공해야 한다.
        db = "error"
    return {"status": "ok", "db": db, "nuclei": nuclei.version()}

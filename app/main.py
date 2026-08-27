"""FastAPI 앱. 루프백 전용 (docs/00 §0.1)."""
from __future__ import annotations

import sqlite3

from fastapi import FastAPI

from app.adapters.nuclei import version as nuclei_version
from app.api import errors, scans, settings_api
from app.repository.db import session

API_PREFIX = "/api/v1"

app = FastAPI(title="REDAR", version="0.3.0", docs_url=f"{API_PREFIX}/docs")

errors.register(app)
app.include_router(scans.router, prefix=API_PREFIX)
app.include_router(settings_api.router, prefix=API_PREFIX)


@app.get(f"{API_PREFIX}/health")
def health() -> dict[str, str | None]:
    try:
        with session() as conn:
            conn.execute("SELECT 1 FROM schema_version LIMIT 1").fetchone()
        db = "connected"
    except sqlite3.Error:
        # DB 부재에도 200. GUI 의 init-db 안내를 위해 헬스체크 자체는 성공 필요
        db = "error"
    return {"status": "ok", "db": db, "nuclei": nuclei_version()}

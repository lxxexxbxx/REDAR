"""FastAPI 앱. 루프백 전용 (docs/00 §0.1)."""
from __future__ import annotations

import sqlite3

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.adapters.nuclei import version as nuclei_version
from app.api import (
    compare, errors, guide, reports, scans, settings_api, templates,
)
from app.config import settings
from app.repository.db import session

API_PREFIX = "/api/v1"

app = FastAPI(title="REDAR", version=__version__, docs_url=f"{API_PREFIX}/docs")

errors.register(app)
# /scans/compare 를 /scans/{scan_id} 보다 먼저 등록한다.
# 뒤에 두면 'compare' 가 scan_id 로 해석되어 404 가 된다
app.include_router(compare.router, prefix=API_PREFIX)
app.include_router(scans.router, prefix=API_PREFIX)
app.include_router(settings_api.router, prefix=API_PREFIX)
app.include_router(guide.router, prefix=API_PREFIX)
app.include_router(templates.router, prefix=API_PREFIX)
app.include_router(reports.router, prefix=API_PREFIX)


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


# GUI 정적 파일. 라우터 등록 뒤 마운트 필요 - API 경로 우선 확보
# 배포 시에는 Tauri 가 서빙하며 (docs/01 §5.3), 이 마운트는 개발·미리보기용
if settings.FONTS_DIR.is_dir():
    app.mount("/fonts", StaticFiles(directory=settings.FONTS_DIR), name="fonts")
if settings.FRONTEND_DIR.is_dir():
    app.mount(
        "/", StaticFiles(directory=settings.FRONTEND_DIR, html=True), name="frontend"
    )

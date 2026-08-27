"""가이드 데이터 라우터. 임포트·항목 조회는 M6."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.repository import guide as guide_repo
from app.repository.db import session

router = APIRouter()


@router.get("/guide/status")
def guide_status() -> dict[str, Any]:
    with session() as conn:
        return guide_repo.status(conn)

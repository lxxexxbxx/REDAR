"""스캔 비교 라우터 (docs/00 §4).

비교는 이 API 전용이다. 보고서에는 반영하지 않는다 (docs/04 §2)
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from app.repository.db import session
from app.services import compare_service

router = APIRouter()


@router.get("/scans/compare")
def compare_scans(
    base: Annotated[str, Query(min_length=1)],
    target: Annotated[str, Query(min_length=1)],
) -> dict[str, Any]:
    with session() as conn:
        return compare_service.compare(conn, base, target)

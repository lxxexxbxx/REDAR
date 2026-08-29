"""가이드 데이터 라우터 (docs/00 §6).

본문 미탑재가 정상 상태. 매핑 테이블은 번들이라 항상 존재 (절대규칙 3)
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, File, Query, UploadFile

from app.repository import guide as guide_repo
from app.repository.db import session
from app.services import guide_importer, guide_service
from app.services.scan_service import ScanError

router = APIRouter()

_MAX_UPLOAD_BYTES = 32 * 1024 * 1024      # 본문 CSV 1MB 대. 이미지 CSV 포함해도 여유


@router.get("/guide/status")
def guide_status() -> dict[str, Any]:
    with session() as conn:
        return guide_repo.status(conn)


@router.post("/guide/import")
async def guide_import(
    file: Annotated[UploadFile, File()],
    images: Annotated[UploadFile | None, File()] = None,
) -> dict[str, Any]:
    """본문 CSV 업로드. 전체 삭제 후 재적재하며 매핑 결과는 보존됨"""
    payload = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(payload) > _MAX_UPLOAD_BYTES:
        raise ScanError("INVALID_REQUEST", "파일이 너무 큽니다.")
    images_text = None
    if images is not None:
        images_payload = await images.read(_MAX_UPLOAD_BYTES + 1)
        if len(images_payload) > _MAX_UPLOAD_BYTES:
            raise ScanError("INVALID_REQUEST", "이미지 목록 파일이 너무 큽니다.")
        images_text = images_payload.decode("utf-8-sig", errors="replace")

    try:
        with session() as conn:
            return guide_importer.import_text(
                conn, payload.decode("utf-8-sig", errors="replace"), images_text
            )
    except guide_importer.ImportError_ as exc:
        raise ScanError(
            "INVALID_REQUEST", exc.message,
            details=[{"field": "file", "reason": e} for e in exc.errors] or None,
        ) from exc


@router.get("/guide/items")
def guide_items(
    category: Annotated[str | None, Query()] = None,
    q: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    with session() as conn:
        items, total = guide_repo.items(
            conn, category=category, query=q, page=page, size=size
        )
    return {"items": items, "page": page, "size": size, "total": total}


@router.get("/scans/{scan_id}/guide")
def scan_guide(scan_id: str) -> dict[str, Any]:
    """스캔의 점검항목 판정. 0건 항목도 사라지지 않음 (절대규칙 4)"""
    with session() as conn:
        from app.repository import scans as scan_repo

        if scan_repo.get_scan(conn, scan_id) is None:
            raise ScanError("NOT_FOUND", "스캔을 찾을 수 없습니다.", status_code=404)
        verdicts = guide_service.verdicts(conn, scan_id)
        status = guide_repo.status(conn)
        detail = {
            row["item_code"]: row
            for row in guide_repo.items(
                conn, codes=[v.item_code for v in verdicts], size=1000
            )[0]
        }
    return {
        "available": status["imported"],
        "summary": guide_service.summary(verdicts),
        "coverage_notice": status["coverage_notice"],
        "items": [
            {
                "item_code": v.item_code,
                "verdict": v.verdict.value,
                "basis": v.basis,
                "finding_count": v.finding_count,
                # 본문 미탑재면 이름·중요도가 비어 있다. 항목 자체는 사라지지 않음
                "item_name": (detail.get(v.item_code) or {}).get("item_name"),
                # 점검항목 중요도는 가이드 원문 값. findings.severity_guide 로 덮지 않음
                "severity_guide": (detail.get(v.item_code) or {}).get("severity_guide"),
                "category": (detail.get(v.item_code) or {}).get("category"),
            }
            for v in verdicts
        ],
    }

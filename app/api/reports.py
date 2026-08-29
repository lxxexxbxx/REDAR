"""보고서 라우터 (docs/00 §5). HTTP 전용."""
from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, ConfigDict, Field

from app.repository import reports as report_repo
from app.repository.db import session
from app.services import report_service

router = APIRouter()


class ReportOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    use_llm: bool = False
    include_guide_mapping: bool = True
    include_evidence: bool = True
    exclude_false_positives: bool = True
    include_guide_cases: bool = True


class CreateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    options: ReportOptions = Field(default_factory=ReportOptions)


@router.post("/reports", status_code=201)
def create_report(body: CreateReportRequest) -> dict[str, Any]:
    with session() as conn:
        view = report_service.create(conn, body.scan_id, body.options.model_dump())
    return {
        "report_id": view["report_id"],
        "scan_id": view["scan_id"],
        "status": view["status"],
        "generated_at": view["generated_at"],
        "files": [f["format"] for f in view["files"]],
        # PDF 는 WebView 인쇄로 파생 (절대규칙 4-1)
        "pdf_note": report_service.PDF_NOTE,
    }


@router.get("/reports")
def list_reports(
    scan_id: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    with session() as conn:
        items, total = report_repo.listing(conn, scan_id=scan_id, page=page, size=size)
    return {"items": items, "page": page, "size": size, "total": total}


@router.get("/reports/{report_id}")
def get_report(report_id: str) -> dict[str, Any]:
    with session() as conn:
        view = report_service.get(conn, report_id)
    return {
        "report_id": view["report_id"],
        "scan_id": view["scan_id"],
        "status": view["status"],
        "generated_at": view["generated_at"],
        "guide_db_available": bool(view["guide_db_available"]),
        "llm_used": bool(view["llm_used"]),
        "files": view["files"],
        "report": view["report"],
    }


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    format: Annotated[Literal["html", "json", "pdf"], Query()] = "html",
) -> Response:
    with session() as conn:
        body, media_type, name = report_service.download(conn, report_id, format)
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.delete("/reports/{report_id}", status_code=204, response_model=None)
def delete_report(report_id: str) -> None:
    with session() as conn:
        report_service.delete(conn, report_id)

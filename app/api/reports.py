"""보고서 라우터 (docs/00 §5). HTTP 전용."""
from __future__ import annotations

from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel, ConfigDict, Field

from app.repository import reports as report_repo
from app.repository.db import session
from app.services import report_service

router = APIRouter()


class ReportOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # use_llm 은 제거됨. 보고서에 생성 문장을 섞으면 원문 대조가 불가능해짐.
    # LLM 은 별도 '조치 가이드' 기능 (POST /remediation/...)
    include_guide_mapping: bool = True
    include_evidence: bool = True
    exclude_false_positives: bool = True


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
        headers={"Content-Disposition": _disposition(name)},
    )


def _disposition(name: str) -> str:
    """파일명에 비ASCII 가 섞이면 헤더 인코딩에서 터진다.

    보고서 파일명은 대상 요약에서 만들어지고 '외 3건'·'포트 12개' 처럼 한글이
    들어갈 수 있다. HTTP 헤더는 latin-1 이라 그대로 넣으면 500 이 됨
    RFC 5987 filename* 로 UTF-8 을 싣고, 구형 클라이언트용 ASCII 이름을 함께 둠
    """
    ascii_name = name.encode("ascii", "replace").decode("ascii").replace("?", "_")
    quoted = quote(name, safe="")
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quoted}"


@router.delete("/reports/{report_id}", status_code=204, response_model=None)
def delete_report(report_id: str) -> None:
    with session() as conn:
        report_service.delete(conn, report_id)

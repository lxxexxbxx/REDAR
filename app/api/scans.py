"""스캔·결과 라우터. HTTP 전용, 비즈니스 판단 없음 (docs/01 §2.1)."""
from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from fastapi import APIRouter, File, Query, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from app.api.errors import not_found
from app.collectors import base as collector_base
from app.domain.enums import FindingStatus, ScanStatus
from app.repository import environment as env_repo
from app.repository import scans as scan_repo
from app.repository.db import session
from app.services import scan_service
from app.services.scan_service import ScanError, ScanRequest

router = APIRouter()

_MAX_TARGET_FILE_BYTES = 1 * 1024 * 1024


class TemplateSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["explicit", "filter", "environment_driven"]
    template_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    severity: list[str] = Field(default_factory=list)
    source: str | None = None


class ScanOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threads: int = Field(default=20, ge=1, le=200)
    timeout_sec: int = Field(default=10, ge=1, le=300)
    retries: int = Field(default=1, ge=0, le=10)
    rate_limit: int | None = Field(default=None, ge=1)


class CreateScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(min_length=1)
    template_selection: TemplateSelection
    collect_environment: bool = True
    options: ScanOptions = Field(default_factory=ScanOptions)


class PatchFindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    note: str | None = None


def _page(items: list[Any], page: int, size: int, total: int) -> dict[str, Any]:
    return {"items": items, "page": page, "size": size, "total": total}


def _csv(value: str | None) -> list[str] | None:
    """'critical,high' -> ['critical','high']."""
    if not value:
        return None
    return [part.strip() for part in value.split(",") if part.strip()]


@router.post("/scans", status_code=202)
def create_scan(body: CreateScanRequest) -> dict[str, Any]:
    selection = body.template_selection
    view = scan_service.get_service().create(
        ScanRequest(
            targets=body.targets,
            mode=selection.mode,
            template_ids=selection.template_ids,
            tags=selection.tags,
            severities=selection.severity,
            collect_environment=body.collect_environment,
            threads=body.options.threads,
            timeout_sec=body.options.timeout_sec,
            retries=body.options.retries,
            rate_limit=body.options.rate_limit,
        )
    )
    return {
        "scan_id": view["scan_id"],
        "status": view.get("status", ScanStatus.QUEUED.value),
        "created_at": view.get("created_at"),
    }


@router.get("/scans")
def list_scans(
    status: str | None = None,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=200)] = 20,
) -> dict[str, Any]:
    with session() as conn:
        items, total = scan_repo.list_scans(conn, status=status, page=page, size=size)
    return _page(items, page, size, total)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str) -> Any:
    with session() as conn:
        view = scan_repo.get_scan(conn, scan_id)
    return view if view else not_found("스캔")


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str) -> Any:
    with session() as conn:
        view = scan_repo.get_scan(conn, scan_id)
    if view is None:
        return not_found("스캔")
    scan_service.get_service().cancel(scan_id)
    return {"scan_id": scan_id, "status": ScanStatus.CANCELED.value}


@router.delete("/scans/{scan_id}", status_code=204, response_model=None)
def delete_scan(scan_id: str) -> Response:
    with session() as conn:
        deleted = scan_repo.delete_scan(conn, scan_id)
    if not deleted:
        return not_found("스캔")
    return Response(status_code=204)


@router.get("/scans/{scan_id}/stream")
def stream_scan(scan_id: str) -> StreamingResponse:
    service = scan_service.get_service()

    def emit():
        for event, data in service.events(scan_id):
            yield f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        emit(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/scans/{scan_id}/findings")
def list_findings(
    scan_id: str,
    severity: str | None = None,
    vuln_type: str | None = None,
    host: str | None = None,
    status: str | None = None,
    sort: Literal["severity", "detected_at", "host", "name"] = "severity",
    order: Literal["asc", "desc"] = "desc",
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Any:
    with session() as conn:
        if scan_repo.get_scan(conn, scan_id) is None:
            return not_found("스캔")
        items, total = scan_repo.list_findings(
            conn, scan_id,
            severity=_csv(severity), vuln_type=_csv(vuln_type),
            host=host, status=status, sort=sort, order=order,
            page=page, size=size,
        )
        # 필터와 무관하게 전체 기준 (docs/00 §4). GUI 요약 배지용
        aggregations = scan_repo.aggregate_findings(conn, scan_id)
    return {**_page(items, page, size, total), "aggregations": aggregations}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> Any:
    with session() as conn:
        view = scan_repo.get_finding(conn, finding_id)
    return view if view else not_found("탐지 결과")


@router.patch("/findings/{finding_id}")
def patch_finding(finding_id: str, body: PatchFindingRequest) -> Any:
    with session() as conn:
        updated = scan_repo.update_finding_status(
            conn, finding_id, body.status.value, body.note
        )
        if not updated:
            return not_found("탐지 결과")
        return scan_repo.get_finding(conn, finding_id)


@router.get("/scans/{scan_id}/environment")
def scan_environment(scan_id: str) -> dict[str, Any]:
    """환경 조사 결과 (docs/00 §4). 미수집이면 빈 목록. 조건부 생략하지 않음"""
    with session() as conn:
        if scan_repo.get_scan(conn, scan_id) is None:
            raise ScanError("NOT_FOUND", "스캔 없음", status_code=404)
        return {"items": env_repo.profiles(conn, scan_id)}


@router.get("/collectors")
def collectors() -> dict[str, Any]:
    """수집기 목록 (docs/00 §4). 확장 가능성을 드러내는 메타 엔드포인트"""
    return {"items": collector_base.describe()}


@router.post("/targets/import")
async def import_targets(file: Annotated[UploadFile, File()]) -> dict[str, Any]:
    content = await file.read(_MAX_TARGET_FILE_BYTES + 1)
    if len(content) > _MAX_TARGET_FILE_BYTES:
        raise scan_service.ScanError(
            "INVALID_REQUEST", "대상 파일 용량 초과. 1MB 이하만 허용"
        )
    targets, invalid = scan_service.parse_target_file(content)
    return {"targets": targets, "count": len(targets), "invalid_lines": invalid}

"""템플릿 라우터 (docs/00 §3). HTTP 전용, 비즈니스 판단 없음 (docs/01 §2.1)."""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict, Field

from app.repository import templates as template_repo
from app.repository.db import session
from app.services import template_builder as builder
from app.services import template_service as service
from app.services import template_validator as validator

router = APIRouter()


class FormRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    form: dict[str, Any]


class ForkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    template_id: str


class ParseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    yaml: str


class ValidateRequest(BaseModel):
    """폼 또는 YAML 중 하나. 폼이 오면 YAML 로 만든 뒤 검증"""

    model_config = ConfigDict(extra="forbid")

    yaml: str | None = None
    form: dict[str, Any] | None = None


class DryrunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    yaml: str
    target: str
    timeout_sec: int = Field(default=10, ge=1, le=120)


def _csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [part.strip() for part in value.split(",") if part.strip()]


@router.get("/templates")
def list_templates(
    source: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    tags: Annotated[str | None, Query()] = None,
    q: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    with session() as conn:
        items, total = template_repo.search(
            conn, source=source, severity=_csv(severity), tags=_csv(tags),
            query=q, page=page, size=size,
        )
    return {"items": items, "page": page, "size": size, "total": total}


@router.get("/templates/schema")
def form_schema() -> dict[str, Any]:
    """빌더 폼 스키마. 필드 정의를 백엔드가 제공해 GUI 수정 없이 반영 (docs/00 §3)"""
    return builder.FORM_SCHEMA


@router.post("/templates/parse")
def parse_template(body: ParseRequest) -> dict[str, Any]:
    """YAML -> 폼. 미지원 문법은 실패가 아니라 unsupported_fields 로 반환"""
    parsed = builder.parse(body.yaml)
    return {
        **parsed,
        "note": "빌더가 지원하지 않는 필드는 YAML 직접 편집 모드에서 확인하세요.",
    }


@router.post("/templates/validate")
def validate_template(body: ValidateRequest) -> dict[str, Any]:
    text = body.yaml
    if text is None:
        if body.form is None:
            raise service.ScanError("INVALID_REQUEST", "yaml 또는 form 중 하나가 필요합니다.")
        text = builder.build(body.form)
    # 검증한 YAML 을 함께 돌려줌. 프론트가 YAML 을 조립하면 조립 규칙이 두 곳에 생김
    return {**validator.validate(text), "yaml": text}


@router.post("/templates/dryrun")
def dryrun_template(body: DryrunRequest) -> dict[str, Any]:
    with session() as conn:
        return service.dryrun(
            conn, body.yaml, body.target, timeout_sec=body.timeout_sec
        )


@router.post("/templates/sync")
def sync_templates() -> dict[str, Any]:
    with session() as conn:
        return service.sync(conn)


@router.post("/templates/reindex")
def reindex_templates() -> dict[str, Any]:
    """templates/ 트리 재색인. 파일을 직접 넣은 경우의 반영 경로 (외부 통신 없음)"""
    with session() as conn:
        return {"indexed": service.index_all(conn)}


@router.post("/templates", status_code=201)
def create_template(body: FormRequest) -> dict[str, Any]:
    with session() as conn:
        return service.create(conn, body.form)


@router.get("/templates/{template_id}")
def get_template(template_id: str) -> dict[str, Any]:
    with session() as conn:
        return service.detail(conn, template_id)


@router.put("/templates/{template_id}")
def update_template(template_id: str, body: FormRequest) -> dict[str, Any]:
    with session() as conn:
        return service.update(conn, template_id, body.form)


@router.delete("/templates/{template_id}", status_code=204, response_model=None)
def delete_template(template_id: str) -> None:
    with session() as conn:
        service.delete(conn, template_id)


@router.post("/templates/{template_id}/fork", status_code=201)
def fork_template(template_id: str, body: ForkRequest) -> dict[str, Any]:
    with session() as conn:
        return service.fork(conn, template_id, body.template_id)

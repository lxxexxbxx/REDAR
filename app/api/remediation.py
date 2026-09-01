"""조치 가이드 라우터. HTTP 전용, 비즈니스 판단 없음 (docs/01 §2.1)."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from app.repository.db import session
from app.services import remediation_service

router = APIRouter()


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "assistant"]
    content: str = Field(min_length=1)


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: list[ChatMessage] = Field(min_length=1)
    # 프롬프트를 실제로 보내기 전 사용자 확인. 기본값은 거부
    confirm: bool = False


@router.get("/remediation/status")
def remediation_status() -> dict[str, Any]:
    """기능 토글·차단 사유. 메뉴 노출 여부를 화면이 이 값으로 결정"""
    with session() as conn:
        return remediation_service.status(conn)


@router.post("/remediation/{report_id}/prompt")
def build_prompt(report_id: str) -> dict[str, Any]:
    with session() as conn:
        return remediation_service.build_prompt(conn, report_id)


@router.post("/remediation/chat")
def chat(body: ChatRequest) -> dict[str, Any]:
    with session() as conn:
        return remediation_service.ask(
            conn,
            [m.model_dump() for m in body.messages],
            confirmed=body.confirm,
        )

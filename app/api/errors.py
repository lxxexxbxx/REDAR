"""공통 오류 응답. 모든 4xx/5xx 를 docs/00 §0.2 형식으로 통일."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.services.scan_service import ScanError

logger = logging.getLogger(__name__)

# HTTP 상태코드 -> 기본 code (docs/00 §0.2)
_DEFAULT_CODES = {
    400: "INVALID_REQUEST",
    404: "NOT_FOUND",
    409: "SCAN_ALREADY_RUNNING",
    422: "INVALID_REQUEST",
    500: "INTERNAL_ERROR",
    503: "LLM_UNAVAILABLE",
}


def error_body(
    code: str, message: str, details: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details or []}}


def error_response(
    status_code: int,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content=error_body(code, message, details)
    )


def not_found(resource: str) -> JSONResponse:
    return error_response(404, "NOT_FOUND", f"{resource}을(를) 찾을 수 없습니다.")


def register(app: FastAPI) -> None:
    @app.exception_handler(ScanError)
    async def _scan_error(_: Request, exc: ScanError) -> JSONResponse:
        return error_response(exc.status_code, exc.code, exc.message, exc.details)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict) and "code" in detail:
            return error_response(
                exc.status_code, detail["code"], detail.get("message", ""),
                detail.get("details"),
            )
        code = _DEFAULT_CODES.get(exc.status_code, "INTERNAL_ERROR")
        return error_response(exc.status_code, code, str(detail))

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        _: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = [
            {
                "field": ".".join(str(p) for p in err.get("loc", ())[1:]),
                "reason": err.get("msg", ""),
            }
            for err in exc.errors()
        ]
        return error_response(
            400, "INVALID_REQUEST", "요청 본문 형식이 올바르지 않습니다.", details
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        # 내부 예외 메시지를 그대로 노출하지 않음. 상세는 로그로만
        logger.exception("처리되지 않은 예외")
        return error_response(500, "INTERNAL_ERROR", "서버 내부 오류가 발생했습니다.")

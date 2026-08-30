"""설정 라우터 (docs/00 §7).

allowlist 기본값이 비어 있음 = 전부 차단이라, 이 API 없이는 GUI 에서 스캔을 시작할 수 없음
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from app.adapters.nuclei import version as nuclei_version
from app.domain import allowlist
from app.repository import settings_repo
from app.repository.db import session

router = APIRouter()


class LlmSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    provider: str | None = None
    model: str | None = None
    endpoint: str | None = None
    temperature: float | None = None
    mask_identifiers: bool | None = None
    require_preview_approval: bool | None = None


class ScanDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threads: int | None = Field(default=None, ge=1, le=200)
    timeout_sec: int | None = Field(default=None, ge=1, le=300)
    retries: int | None = Field(default=None, ge=0, le=10)


class ExternalEndpointPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str
    enabled: bool


class UpdateSettingsRequest(BaseModel):
    """부분 갱신. 보내지 않은 항목은 유지."""

    model_config = ConfigDict(extra="forbid")

    offline_mode: bool | None = None
    target_allowlist: list[str] | None = None
    llm: LlmSettings | None = None
    scan_defaults: ScanDefaults | None = None
    external_endpoints: list[ExternalEndpointPatch] | None = None


def _view(raw: dict[str, str]) -> dict[str, Any]:
    offline = settings_repo.as_bool(raw.get("offline_mode"), default=True)
    endpoints = []
    for key in settings_repo.EXTERNAL_ENDPOINT_KEYS:
        enabled = settings_repo.as_bool(raw.get(f"ext_{key}_enabled"))
        endpoints.append({
            "key": key,
            # 오프라인 모드가 켜져 있으면 개별 설정과 무관하게 강제 비활성 (docs/00 §7)
            "enabled": enabled and not offline,
            "configured": enabled,
            # 기본 URL 은 settings_defaults.csv 가 넣어준 ext_<key>_url
            "url": raw.get(f"ext_{key}_url") or "",
        })
    return {
        "offline_mode": offline,
        "target_allowlist": settings_repo.as_list(raw.get("target_allowlist")),
        "llm": {
            "enabled": settings_repo.as_bool(raw.get("llm_enabled")),
            "provider": raw.get("llm_provider"),
            "model": raw.get("llm_model"),
            "endpoint": raw.get("llm_endpoint"),
            "temperature": float(raw.get("llm_temperature") or 0),
            "mask_identifiers": settings_repo.as_bool(
                raw.get("llm_mask_identifiers"), default=True
            ),
            "require_preview_approval": settings_repo.as_bool(
                raw.get("llm_require_preview_approval"), default=True
            ),
        },
        "scan_defaults": {
            "threads": settings_repo.as_int(raw.get("scan_default_threads"), 20),
            "timeout_sec": settings_repo.as_int(raw.get("scan_default_timeout"), 10),
            "retries": settings_repo.as_int(raw.get("scan_default_retries"), 1),
        },
        "external_endpoints": endpoints,
        "tool": {
            "nuclei_version": nuclei_version(),
            "guide_version": raw.get("guide_version"),
        },
    }


class LlmPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str | None = None
    report_id: str | None = None


@router.post("/settings/llm/preview")
def llm_preview(body: LlmPreviewRequest) -> dict[str, Any]:
    """전송 데이터 미리보기. 응답 본문·추출값은 포함되지 않음 (docs/01 §7.4)"""
    from app.domain.ids import new_id
    from app.report import builder
    from app.repository import reports as report_repo
    from app.services import narrative_service
    from app.services.scan_service import ScanError

    with session() as conn:
        if body.report_id:
            view = report_repo.get(conn, body.report_id)
            if view is None or view["report"] is None:
                raise ScanError("NOT_FOUND", "보고서 없음", status_code=404)
            report = view["report"]
        elif body.scan_id:
            report = builder.build(conn, body.scan_id, report_id=new_id("rpt"))
        else:
            raise ScanError("INVALID_REQUEST", "scan_id 또는 report_id 필요")
        return narrative_service.preview(conn, report)


@router.post("/settings/llm/test")
def llm_test() -> dict[str, Any]:
    """연결 테스트. 오프라인 모드에서는 호출하지 않음 (절대규칙 5)"""
    from app.adapters.llm import get_provider
    from app.adapters.llm.base import LlmError

    with session() as conn:
        raw = settings_repo.get_all(conn)
        offline = settings_repo.offline_mode(conn)
        enabled = settings_repo.as_bool(raw.get("ext_llm_api_enabled"))

    if offline:
        return {"ok": False, "reason": "오프라인 모드. LLM 호출 안 함"}
    if not enabled:
        return {"ok": False, "reason": "LLM 통신 지점이 비활성 상태입니다."}

    provider = get_provider(raw.get("llm_provider"), {
        "endpoint": raw.get("llm_endpoint"),
        "api_key": raw.get("llm_api_key"),
        "model": raw.get("llm_model"),
    })
    if provider.name == "null":
        return {"ok": False, "reason": "Provider 미설정 · NullProvider"}
    try:
        text = provider.narrate("executive_summary", {"total_findings": 0})
    except LlmError as exc:
        return {"ok": False, "reason": str(exc), "provider": provider.name}
    return {
        "ok": bool(text), "provider": provider.name, "model": provider.model,
        # 응답 본문을 그대로 돌려주지 않음. 길이만 보고
        "response_length": len(text or ""),
    }


@router.get("/settings")
def get_settings() -> dict[str, Any]:
    with session() as conn:
        return _view(settings_repo.get_all(conn))


@router.put("/settings")
def update_settings(body: UpdateSettingsRequest) -> dict[str, Any]:
    values: dict[str, Any] = {}
    if body.offline_mode is not None:
        values["offline_mode"] = body.offline_mode
    if body.target_allowlist is not None:
        # URL 로 입력해도 등록되도록 호스트로 정규화 (절대규칙 6)
        entries = [allowlist.normalize_entry(t) for t in body.target_allowlist]
        values["target_allowlist"] = list(dict.fromkeys(t for t in entries if t))
    if body.llm is not None:
        for field_name, value in body.llm.model_dump(exclude_none=True).items():
            values[f"llm_{field_name}"] = value
    if body.scan_defaults is not None:
        mapping = {
            "threads": "scan_default_threads",
            "timeout_sec": "scan_default_timeout",
            "retries": "scan_default_retries",
        }
        for field_name, value in body.scan_defaults.model_dump(
            exclude_none=True
        ).items():
            values[mapping[field_name]] = value
    if body.external_endpoints is not None:
        known = set(settings_repo.EXTERNAL_ENDPOINT_KEYS)
        for endpoint in body.external_endpoints:
            if endpoint.key not in known:
                # 목록 밖의 통신 지점을 설정으로 추가할 수 없음 (절대규칙 5)
                from app.services.scan_service import ScanError

                raise ScanError(
                    "INVALID_REQUEST",
                    f"허용되지 않은 외부 통신 지점: {endpoint.key}",
                    details=[{"field": "external_endpoints", "reason": endpoint.key}],
                )
            values[f"ext_{endpoint.key}_enabled"] = endpoint.enabled

    with session() as conn:
        if values:
            settings_repo.put_many(conn, values)
        return _view(settings_repo.get_all(conn))

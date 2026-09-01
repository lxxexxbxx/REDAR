"""설정 라우터 (docs/00 §7).

allowlist 기본값이 비어 있음 = 전부 차단이라, 이 API 없이는 GUI 에서 스캔을 시작할 수 없음
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from app.adapters.llm.masking import Masker
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
    # 조치 가이드 기능 토글. 꺼져 있으면 GUI 메뉴 자체가 없음
    remediation_guide_enabled: bool | None = None
    # 자격증명. 저장만 하고 조회 응답에는 넣지 않음
    api_key: str | None = None


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
            # 조치 가이드 메뉴 노출 여부. 꺼져 있으면 화면 자체가 없음
            "remediation_guide_enabled": settings_repo.as_bool(
                raw.get("llm_remediation_guide_enabled")
            ),
            # 키 자체는 절대 내보내지 않음. 설정 여부만 알려줌
            "api_key_set": bool(raw.get("llm_api_key")),
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
    """전송 데이터 미리보기. 응답 본문·추출값은 포함되지 않음 (docs/01 §7.4).

    보고서 서술 레이어가 제거되면서 대상이 조치 가이드 전송값으로 바뀜.
    화면은 프롬프트 생성 결과로도 확인하지만, 보내기 전에 무엇이 나가는지
    따로 볼 수 있어야 함
    """
    from app.repository import reports as report_repo
    from app.services import remediation_service
    from app.services.scan_service import ScanError

    with session() as conn:
        if not body.report_id:
            raise ScanError("INVALID_REQUEST", "report_id 필요")
        view = report_repo.get(conn, body.report_id)
        if view is None or view["report"] is None:
            raise ScanError("NOT_FOUND", "보고서 없음", status_code=404)

        raw = settings_repo.get_all(conn)
        masker = (
            Masker() if settings_repo.as_bool(
                raw.get("llm_mask_identifiers"), default=True
            ) else None
        )
        context = remediation_service.report_context(view["report"])
        return {
            "masked": masker is not None,
            "mask_map_size": len(masker.mapping) if masker else 0,
            "payload": masker.mask_context(context) if masker else context,
            "excluded": ["요청·응답 원문", "추출값", "내부 경로", "자격증명"],
        }


@router.post("/settings/llm/test")
def llm_test() -> dict[str, Any]:
    """연결 테스트. 오프라인 모드에서는 호출하지 않음 (절대규칙 5)"""
    from app.adapters.llm import get_provider
    from app.adapters.llm.base import LlmError
    from app.services import remediation_service

    with session() as conn:
        raw = settings_repo.get_all(conn)
        offline = settings_repo.offline_mode(conn)
        enabled = settings_repo.as_bool(raw.get("ext_llm_api_enabled"))

    if offline:
        return {"ok": False, "reason": "오프라인 모드. LLM 호출 안 함"}
    if not enabled:
        return {"ok": False, "reason": "LLM 통신 지점 비활성"}
    if not raw.get("llm_api_key"):
        return {"ok": False, "reason": "API 키 미입력"}

    # Provider 미지정은 조치 가이드와 같은 기본값을 씀 (remediation_service)
    provider = get_provider(
        remediation_service.provider_name(raw),
        {
            "endpoint": raw.get("llm_endpoint"),
            "api_key": raw.get("llm_api_key"),
            "model": raw.get("llm_model"),
        },
    )
    if provider.name == "null":
        return {"ok": False, "reason": "알 수 없는 Provider"}
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

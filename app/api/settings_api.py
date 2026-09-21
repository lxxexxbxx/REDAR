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

    provider: str | None = None
    model: str | None = None
    endpoint: str | None = None
    mask_identifiers: bool | None = None
    # 조치 가이드 기능 토글. 꺼져 있으면 GUI 메뉴 자체가 없음
    remediation_guide_enabled: bool | None = None
    # 자격증명. 저장만 하고 조회 응답에는 넣지 않음
    api_key: str | None = None


class ScanDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threads: int | None = Field(default=None, ge=1, le=200)
    timeout_sec: int | None = Field(default=None, ge=1, le=300)
    retries: int | None = Field(default=None, ge=0, le=10)
    # 초당 요청 상한. 0 = 제한 없음
    rate_limit: int | None = Field(default=None, ge=0, le=10000)
    # WordPress 전수 열거 opt-in. 켜면 요청 약 12.5만 증가
    wp_full_enumeration: bool | None = None


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
        endpoints.append(
            {
                "key": key,
                # 오프라인 모드가 켜져 있으면 개별 설정과 무관하게 강제 비활성 (docs/00 §7)
                "enabled": enabled and not offline,
                "configured": enabled,
                # 기본 URL 은 settings_defaults.csv 가 넣어준 ext_<key>_url
                "url": raw.get(f"ext_{key}_url") or "",
            }
        )
    return {
        "offline_mode": offline,
        "target_allowlist": settings_repo.as_list(raw.get("target_allowlist")),
        "llm": {
            "provider": raw.get("llm_provider"),
            "model": raw.get("llm_model"),
            "endpoint": raw.get("llm_endpoint"),
            "mask_identifiers": settings_repo.as_bool(
                raw.get("llm_mask_identifiers"), default=True
            ),
            # 조치 가이드 메뉴 노출 여부. 꺼져 있으면 화면 자체가 없음
            "remediation_guide_enabled": settings_repo.as_bool(
                raw.get("llm_remediation_guide_enabled")
            ),
            # 키 자체는 절대 내보내지 않음. 설정 여부만 알려줌
            "api_key_set": bool(raw.get("llm_api_key")),
        },
        "scan_defaults": {
            **settings_repo.scan_defaults(raw),
            "wp_full_enumeration": settings_repo.as_bool(
                raw.get("scan_wp_full_enumeration")
            ),
        },
        "external_endpoints": endpoints,
        "tool": {
            "nuclei_version": nuclei_version(),
            "guide_version": raw.get("guide_version"),
        },
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
            "rate_limit": "scan_default_rate_limit",
            "wp_full_enumeration": "scan_wp_full_enumeration",
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

"""의존성 관리 라우터 (nuclei 등).

세 경로를 제공. 폐쇄망에서도 도구를 쓸 수 있어야 함
  GET    /dependencies               상태 조회
  POST   /dependencies/{key}/import  파일 반입 (통신 없음)
  PUT    /dependencies/{key}/path    경로 지정 (통신 없음)
  POST   /dependencies/{key}/install 자동 설치 (외부 통신 4번. 명시 동의 필요)
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, File, UploadFile
from pydantic import BaseModel, ConfigDict

from app.repository.db import session
from app.services import dependency_service
from app.services.scan_service import ScanError

router = APIRouter()

_MAX_UPLOAD_BYTES = 512 * 1024 * 1024


class PathRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # None 이면 지정 해제 후 자동 탐색으로 되돌림
    path: str | None = None


class InstallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # 설정만으로 자동 실행되지 않음. 요청마다 사용자가 동의함
    confirm: bool = False


@router.get("/dependencies")
def list_dependencies() -> dict[str, Any]:
    with session() as conn:
        return dependency_service.status(conn)


@router.put("/dependencies/{key}/path")
def set_dependency_path(key: str, body: PathRequest) -> dict[str, Any]:
    with session() as conn:
        return dependency_service.set_path(conn, key, body.path)


@router.post("/dependencies/{key}/import")
async def import_dependency(
    key: str, file: Annotated[UploadFile, File()]
) -> dict[str, Any]:
    payload = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(payload) > _MAX_UPLOAD_BYTES:
        raise ScanError("INVALID_REQUEST", "파일이 너무 큽니다.")
    with session() as conn:
        return dependency_service.import_binary(conn, key, payload)


@router.post("/dependencies/{key}/install")
def install_dependency(key: str, body: InstallRequest) -> dict[str, Any]:
    with session() as conn:
        return dependency_service.install(conn, key, confirmed=body.confirm)

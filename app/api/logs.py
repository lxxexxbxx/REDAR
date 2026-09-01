"""처리 과정 로그 조회. HTTP 전용 (docs/01 §2.1).

메모리 버퍼만 읽는다. 파일로 남기지 않으므로 조회 시점에 없는 줄은 사라진 것
"""
from __future__ import annotations

from typing import Annotated, Any

from datetime import datetime

from fastapi import APIRouter, Query, Response

from app.adapters import logbuffer

router = APIRouter()


@router.get("/logs")
def read_logs(
    after: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
) -> dict[str, Any]:
    """after 이후의 줄. 화면이 마지막 seq 를 들고 폴링"""
    items = logbuffer.entries(after=after, limit=limit)
    return {
        "items": items,
        # 다음 폴링에 쓸 커서. 비어 있어도 진행하도록 현재 최대값을 함께 줌
        "cursor": items[-1]["seq"] if items else after,
        "latest": logbuffer.latest_seq(),
    }


@router.get("/logs/download")
def download_logs() -> Response:
    """버퍼에 남아 있는 줄을 텍스트 파일로. 서버는 여전히 저장하지 않는다.

    사용자가 원할 때만 내보낸다. 자동 저장하면 용량이 계속 늘어남
    """
    lines = [
        f"{datetime.fromtimestamp(e['at']).strftime('%Y-%m-%d %H:%M:%S')}"
        f" {e['level']:<7} {e['source']}  {e['message']}"
        for e in logbuffer.entries(limit=logbuffer._MAX)
    ]
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    return Response(
        content="\n".join(lines) + "\n",
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="redar_log_{stamp}.txt"',
        },
    )

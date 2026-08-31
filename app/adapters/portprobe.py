"""대상 포트 응답 확인.

nuclei 에는 포트 범위 옵션이 없어 REDAR 가 개별 대상으로 펼친다(domain/target_range).
펼친 대상 전부에 템플릿을 돌리면 닫힌 포트에도 요청이 나가 시간이 낭비된다.
연결만 먼저 시도해 응답하는 포트를 추려내면 실제 스캔 대상이 크게 줄어든다

TCP 연결 시도뿐이다. raw socket 도, 관리자 권한도 쓰지 않는다.
브라우저가 접속할 때 하는 동작과 같으며 허용 목록 통제를 이미 통과한 대상에만 한다
"""
from __future__ import annotations

import logging
import socket
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor

from app.domain import url as urlmod

logger = logging.getLogger(__name__)

# 응답 대기. 스캔 타임아웃과 별개다. 연결 수립만 보므로 짧아도 된다
DEFAULT_TIMEOUT_SEC = 0.4
# 동시 확인 수. 순차로 하면 1024 포트에 timeout * 1024 가 그대로 걸린다
DEFAULT_WORKERS = 100


def _endpoint(target: str) -> tuple[str, int] | None:
    """대상 문자열 -> (host, port). 포트를 확정할 수 없으면 None"""
    try:
        parts = urlmod.parse(target)
    except ValueError:
        return None
    if parts.port is None:
        return None
    return parts.host, parts.port


def is_open(host: str, port: int, timeout: float = DEFAULT_TIMEOUT_SEC) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        # 연결 거부·타임아웃·이름 해석 실패 전부 '응답 없음' 으로 본다
        return False


def reachable(
    targets: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT_SEC,
    workers: int = DEFAULT_WORKERS,
) -> list[str]:
    """응답하는 대상만 입력 순서대로 반환.

    포트를 확정할 수 없는 대상(스킴·포트 없음)은 확인하지 않고 통과시킨다.
    nuclei 가 기본 포트로 처리하므로 여기서 버리면 멀쩡한 대상이 사라진다
    """
    if not targets:
        return []

    checks: dict[str, tuple[str, int]] = {}
    passthrough: list[str] = []
    for target in targets:
        endpoint = _endpoint(target)
        if endpoint is None:
            passthrough.append(target)
        else:
            checks[target] = endpoint

    open_targets: set[str] = set(passthrough)
    if checks:
        with ThreadPoolExecutor(max_workers=min(workers, len(checks))) as pool:
            results = pool.map(
                lambda item: (item[0], is_open(*item[1], timeout=timeout)),
                checks.items(),
            )
            open_targets |= {target for target, ok in results if ok}

    return [t for t in targets if t in open_targets]

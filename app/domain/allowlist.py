"""스캔 대상 allowlist 판정 (절대규칙 6).

기본값은 비어 있음 = 전부 차단. 버그가 아니라 의도된 동작 (docs/01 §7.2).
통제 없이 임의 URL 을 받으면 공용 스캔 대행 도구가 됨
"""
from __future__ import annotations

import ipaddress
from collections.abc import Sequence

from app.domain import url as urlmod


def _as_network(entry: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _as_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def host_allowed(host: str, allowlist: Sequence[str]) -> bool:
    """호스트 단독 판정. 포트는 무관.

    호스트명은 정확 일치만. DNS 로 IP 를 얻어 CIDR 대조하는 방식은 쓰지 않음
    이름 해석 결과에 따라 허용 범위가 바뀌고 조회 자체가 아웃바운드 통신
    """
    if not host or not allowlist:
        return False

    target = host.strip().lower()
    address = _as_address(target)

    for raw_entry in allowlist:
        entry = str(raw_entry).strip().lower()
        if not entry:
            continue
        if entry == target:
            return True
        if address is not None:
            network = _as_network(entry)
            if network is not None and address.version == network.version:
                if address in network:
                    return True
    return False


def target_allowed(target: str, allowlist: Sequence[str]) -> bool:
    """'http://host:8080/path' 형태 포함 판정. 해석 불가 대상은 차단."""
    try:
        parts = urlmod.parse(target)
    except ValueError:
        return False
    return host_allowed(parts.host, allowlist)


def rejected_targets(targets: Sequence[str], allowlist: Sequence[str]) -> list[str]:
    """거부 대상 목록. 400 응답의 details 에 사용."""
    return [t for t in targets if not target_allowed(t, allowlist)]

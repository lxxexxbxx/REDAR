"""포트 범위 입력 해석 · 전개.

nuclei 에는 포트 범위 옵션이 없다. HTTP 템플릿은 대상 URL 에 적힌 포트만 사용하므로
'localhost:33-4444' 를 개별 대상으로 펼쳐 넘기는 일은 REDAR 몫

표기는 두 층으로 나눔 (docs/01 §2.1 경계와 동일한 이유)
  - 스캔 요약·보고서 개요: 사용자가 입력한 범위 원문 유지
  - 개별 탐지 결과·조치 대상: 실제 발견된 포트
범위로 뭉쳐 표기하면 어느 포트를 막아야 할지 알 수 없고 재현도 불가
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.domain import url as urlmod

# 확인 없이 진행하는 상한. 넘으면 사용자에게 되물음.
# 웹 서비스가 흩어져 있는 랩 환경에서 300 포트 남짓은 일상적인 범위
CONFIRM_THRESHOLD = 300
# 절대 상한. 대상이 곱으로 늘어 스캔 시간과 대상 부하가 함께 커짐
MAX_PORTS = 1024

_PORT_MIN, _PORT_MAX = 1, 65535

# 'host:33-4444' 또는 'http://host:33-4444/path'. 스킴·경로는 그대로 보존
_RANGE_RE = re.compile(
    r"^(?P<prefix>(?:[a-z][a-z0-9+.\-]*://)?[^/:]+):"
    r"(?P<start>\d{1,5})-(?P<end>\d{1,5})"
    r"(?P<suffix>[/?].*)?$",
    re.I,
)


class RangeError(ValueError):
    """범위 표기 오류. 호출자가 사용자 메시지로 변환"""


@dataclass(frozen=True, slots=True)
class Expansion:
    """전개 결과. raw 는 화면·보고서 표기에, targets 는 nuclei 실행에 사용"""

    raw: list[str]
    targets: list[str]

    @property
    def expanded(self) -> bool:
        return len(self.targets) > len(self.raw)


def is_range(text: str) -> bool:
    return _RANGE_RE.match((text or "").strip()) is not None


def describe(text: str) -> str | None:
    """범위 입력의 사람이 읽는 표기. 범위가 아니면 None"""
    match = _RANGE_RE.match((text or "").strip())
    if match is None:
        return None
    return f"{match.group('prefix')} · 포트 {match.group('start')}~{match.group('end')}"


def _ports(start: int, end: int) -> range:
    if start > end:
        raise RangeError(f"시작 포트가 끝 포트보다 큼: {start}-{end}")
    if not (_PORT_MIN <= start and end <= _PORT_MAX):
        raise RangeError(f"포트는 {_PORT_MIN}~{_PORT_MAX} 범위: {start}-{end}")
    return range(start, end + 1)


def expand_one(text: str) -> list[str]:
    """대상 1건 전개. 범위가 아니면 원문 그대로 1건"""
    stripped = (text or "").strip()
    match = _RANGE_RE.match(stripped)
    if match is None:
        return [stripped] if stripped else []

    prefix, suffix = match.group("prefix"), match.group("suffix") or ""
    ports = _ports(int(match.group("start")), int(match.group("end")))
    return [f"{prefix}:{port}{suffix}" for port in ports]


def expand(targets: list[str]) -> Expansion:
    """입력 전체 전개. 원문과 실행 대상을 함께 돌려줌

    중복 제거는 순서를 유지. 'localhost:80' 과 'localhost:79-81' 을 함께 넣어도
    같은 대상을 두 번 스캔하지 않음
    """
    raw = [t.strip() for t in targets if t and t.strip()]
    seen: dict[str, None] = {}
    for entry in raw:
        for target in expand_one(entry):
            seen.setdefault(target, None)

    expanded = list(seen)
    if len(expanded) > MAX_PORTS:
        raise RangeError(
            f"대상 {len(expanded)}건. 한 번에 {MAX_PORTS}건까지만 허용. 범위 축소 필요"
        )
    return Expansion(raw=raw, targets=expanded)


def hosts(targets: list[str]) -> list[str]:
    """허용 목록 판정용 호스트. 범위 표기는 포트를 떼고 해석

    전개 결과 전체를 판정하면 같은 호스트를 수천 번 검사하게 됨
    """
    found: dict[str, None] = {}
    for entry in targets:
        match = _RANGE_RE.match((entry or "").strip())
        candidate = f"{match.group('prefix')}" if match else entry
        try:
            found.setdefault(urlmod.parse(candidate).host, None)
        except ValueError:
            # 해석 불가 대상은 판정 단계에서 거부됨. 여기서는 통과시킴
            found.setdefault(str(entry).strip(), None)
    return list(found)

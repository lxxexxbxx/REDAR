"""nuclei stderr stats -> 진행률.

`-stats -si 5` 가 stderr 로 내는 한 줄을 해석.
형식이 릴리스마다 바뀔 수 있어 해석 실패 시 None 반환, 예외 없음
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# '[0:00:05] | Templates: 1234 | Hosts: 1 | Requests: 615/1234 (49%) | Matched: 5'
_PAIR_RE = re.compile(r"([A-Za-z][A-Za-z ]*?):\s*([^|]+)")
_FRACTION_RE = re.compile(r"(\d+)\s*/\s*(\d+)")


@dataclass(frozen=True, slots=True)
class Progress:
    percent: float | None = None
    requests_done: int | None = None
    requests_total: int | None = None
    templates: int | None = None
    hosts: int | None = None
    matched: int | None = None
    errors: int | None = None


def _int(text: str) -> int | None:
    try:
        return int(text.strip())
    except ValueError:
        return None


def parse_stats_line(line: str) -> Progress | None:
    """stats 한 줄 해석. stats 줄이 아니면 None."""
    if "|" not in line:
        return None
    pairs = {k.strip().lower(): v.strip() for k, v in _PAIR_RE.findall(line)}
    if not pairs:
        return None

    done = total = percent = None
    requests = pairs.get("requests")
    if requests:
        fraction = _FRACTION_RE.search(requests)
        if fraction:
            done, total = int(fraction.group(1)), int(fraction.group(2))
            # 표기된 퍼센트를 그대로 쓰지 않고 재계산. 반올림 표기 차이 제거
            percent = round(done / total * 100, 1) if total else None

    progress = Progress(
        percent=percent,
        requests_done=done,
        requests_total=total,
        templates=_int(pairs.get("templates", "")),
        hosts=_int(pairs.get("hosts", "")),
        matched=_int(pairs.get("matched", "")),
        errors=_int(pairs.get("errors", "")),
    )
    # 아무 값도 못 뽑으면 stats 줄이 아님
    if all(getattr(progress, f) is None for f in Progress.__slots__):
        return None
    return progress

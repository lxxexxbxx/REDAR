"""nuclei stderr stats -> 진행률.

`-stats -si 5` 가 stderr 로 내는 한 줄을 해석.
형식이 릴리스마다 바뀔 수 있어 해석 실패 시 None 반환, 예외 없음
"""
from __future__ import annotations

import json
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


def _percent(done: int | None, total: int | None) -> float | None:
    """완료 비율. nuclei 는 리다이렉트 등으로 완료 수가 총량을 넘기도 함 (실측 4/3) - 100 에서 자름"""
    if done is None or not total:
        return None
    return min(100.0, round(done / total * 100, 1))


def _parse_json(text: str) -> Progress | None:
    """nuclei 3.x 는 -jsonl 과 함께 stats 를 JSON 한 줄로 냄 (v3.11.1 실측).

    값이 전부 문자열. requests = 완료 요청 수, total = 전체 요청 수
    """
    try:
        data = json.loads(text)
    except ValueError:
        return None
    # 탐지 결과 등 다른 JSON 과 구분. stats 줄은 requests·total 을 함께 가짐
    if not isinstance(data, dict) or "requests" not in data or "total" not in data:
        return None
    done = _int(str(data.get("requests", "")))
    total = _int(str(data.get("total", "")))
    return Progress(
        percent=_percent(done, total),
        requests_done=done,
        requests_total=total,
        templates=_int(str(data.get("templates", ""))),
        hosts=_int(str(data.get("hosts", ""))),
        matched=_int(str(data.get("matched", ""))),
        errors=_int(str(data.get("errors", ""))),
    )


def parse_stats_line(line: str) -> Progress | None:
    """stats 한 줄 해석. stats 줄이 아니면 None."""
    text = line.strip()
    if text.startswith("{"):
        return _parse_json(text)
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
            percent = _percent(done, total)

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

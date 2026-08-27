"""심각도 환산. CVSS -> Severity -> SeverityGuide.

환산표는 app/config/severity_map.yaml 로 분리.
보고서 부록에 표를 그대로 첨부하므로 코드에 숫자 하드코딩 시 부록과 불일치 (docs/00 §6.1)
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

import yaml

from app.domain.enums import Severity, SeverityGuide

_MAP_PATH = Path(__file__).resolve().parents[1] / "config" / "severity_map.yaml"


class Band(NamedTuple):
    min: float
    max: float
    severity: Severity
    severity_guide: SeverityGuide


@lru_cache(maxsize=1)
def bands() -> tuple[Band, ...]:
    """환산표. 높은 구간부터 정렬."""
    raw = yaml.safe_load(_MAP_PATH.read_text(encoding="utf-8"))["bands"]
    parsed = [
        Band(
            float(b["min"]),
            float(b["max"]),
            Severity(b["severity"]),
            SeverityGuide(b["severity_guide"]),
        )
        for b in raw
    ]
    return tuple(sorted(parsed, key=lambda b: b.min, reverse=True))


def severity_from_cvss(score: float | None) -> Severity:
    """CVSS 점수 -> Severity. None·0.0(미산정)은 info."""
    if score is None:
        return Severity.INFO
    for band in bands():
        if score >= band.min:
            return band.severity
    return Severity.INFO


@lru_cache(maxsize=8)
def guide_from_severity(severity: Severity) -> SeverityGuide:
    """Severity -> SeverityGuide. critical/high 둘 다 '상'이나 구간 분리로 충돌 없음."""
    for band in bands():
        if band.severity is severity:
            return band.severity_guide
    raise ValueError(f"환산표에 없는 severity: {severity}")


def convert(score: float | None) -> tuple[Severity, SeverityGuide]:
    severity = severity_from_cvss(score)
    return severity, guide_from_severity(severity)

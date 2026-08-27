"""nuclei JSONL -> Finding 정규화.

한 줄 = 탐지 1건. 파일 완성 후 일괄 읽기 대신 라인 단위 처리 (docs/01 §3.1).
한 줄이 깨져도 스캔 전체를 중단하지 않고 해당 줄만 건너뜀
"""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime

from app.domain import url as urlmod
from app.domain.enums import Severity, TemplateSource
from app.domain.fingerprint import make_fingerprint
from app.domain.ids import new_id
from app.domain.models import (
    EVIDENCE_MAX_BYTES,
    EVIDENCE_TRUNCATED_MARKER,
    Evidence,
    Finding,
    Target,
)
from app.domain.severity import guide_from_severity, severity_from_cvss
from app.domain.vuln_type import TypeRule, normalize

logger = logging.getLogger(__name__)

_NANOS_RE = re.compile(r"\.(\d+)")


def truncate_evidence(text: str | None, limit: int = EVIDENCE_MAX_BYTES) -> str | None:
    """32KB 초과분 절단 + 마커 부착.

    findings 테이블에 절단 플래그 컬럼이 없어 본문 마커로 표시 (models.py 참조).
    바이트 기준 절단 후 깨진 멀티바이트 문자는 폐기
    """
    if text is None:
        return None
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    head = encoded[:limit].decode("utf-8", errors="ignore")
    return head + EVIDENCE_TRUNCATED_MARKER


def is_truncated(text: str | None) -> bool:
    return bool(text) and text.endswith(EVIDENCE_TRUNCATED_MARKER)


def _as_list(value: object) -> list[str]:
    """nuclei 는 같은 필드를 문자열/배열로 혼용 출력."""
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value)]


def _as_float(value: object) -> float | None:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _resolve_target(raw: dict) -> Target:
    """matched-at 우선. 실패 시 url -> host 필드로 후퇴.

    matched-at 은 매칭 지점의 전체 URL 이라 경로까지 포함하므로 1순위
    """
    candidates = [raw.get("matched-at"), raw.get("url"), raw.get("host")]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            parts = urlmod.parse(str(candidate))
        except ValueError:
            continue
        port = parts.port
        if port is None:
            port = _as_int(raw.get("port"))
        return Target(
            raw=str(raw.get("matched-at") or candidate),
            scheme=parts.scheme or raw.get("scheme") or None,
            host=parts.host,
            port=port,
            path=parts.path or None,
        )
    raise ValueError("host 확보 불가")


def _as_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _resolve_severity(info: dict, cvss_score: float | None) -> Severity:
    """info.severity 우선. 'unknown' 등 미지의 값은 CVSS 로 환산."""
    try:
        return Severity(str(info.get("severity", "")).lower())
    except ValueError:
        return severity_from_cvss(cvss_score)


def _resolve_detected_at(raw: dict) -> datetime:
    """nuclei timestamp 는 RFC3339. 나노초 9자리는 파이썬이 못 읽어 6자리로 절단."""
    text = str(raw.get("timestamp") or "").strip()
    if text:
        normalized = _NANOS_RE.sub(lambda m: "." + m.group(1)[:6], text)
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            logger.debug("timestamp 해석 실패, 현재 시각 사용")
    return datetime.now().astimezone()


def parse_line(
    line: str,
    *,
    scan_id: str,
    rules: Sequence[TypeRule],
    template_source: TemplateSource = TemplateSource.OFFICIAL,
) -> Finding | None:
    """JSONL 한 줄 -> Finding. 해석 불가 시 None."""
    text = line.strip()
    if not text:
        return None
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("JSONL 파싱 실패, 해당 줄 건너뜀")
        return None
    if not isinstance(raw, dict):
        return None

    template_id = str(raw.get("template-id") or "").strip()
    if not template_id:
        logger.warning("template-id 없음, 해당 줄 건너뜀")
        return None

    try:
        target = _resolve_target(raw)
    except ValueError:
        logger.warning("대상 해석 실패, 해당 줄 건너뜀: %s", template_id)
        return None

    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    classification = (
        info.get("classification")
        if isinstance(info.get("classification"), dict)
        else {}
    )

    cve_ids = _as_list(classification.get("cve-id"))
    cwe_ids = [c.upper() for c in _as_list(classification.get("cwe-id"))]
    cvss_score = _as_float(classification.get("cvss-score"))
    tags = _as_list(info.get("tags"))

    severity = _resolve_severity(info, cvss_score)
    matcher_name = raw.get("matcher-name") or None

    return Finding(
        finding_id=new_id("fnd"),
        scan_id=scan_id,
        # 탐지 시점 계산 후 저장 (절대규칙 7)
        fingerprint=make_fingerprint(
            template_id, target.host, target.port, target.path, matcher_name
        ),
        source="nuclei",
        template_id=template_id,
        template_source=template_source,
        matcher_name=matcher_name,
        target=target,
        name=str(info.get("name") or template_id),
        description=info.get("description") or None,
        vuln_type=normalize(
            tags=tags, cwe_ids=cwe_ids, template_id=template_id, rules=rules
        ),
        severity=severity,
        severity_guide=guide_from_severity(severity),
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        cvss_score=cvss_score,
        cvss_vector=classification.get("cvss-metrics") or None,
        evidence=Evidence(
            request=truncate_evidence(raw.get("request")),
            response=truncate_evidence(raw.get("response")),
            extracted_values=_as_list(raw.get("extracted-results")),
            curl_command=raw.get("curl-command") or None,
        ),
        detected_at=_resolve_detected_at(raw),
    )


def parse_stream(
    lines: Iterable[str],
    *,
    scan_id: str,
    rules: Sequence[TypeRule],
    template_source: TemplateSource = TemplateSource.OFFICIAL,
) -> Iterator[Finding]:
    for line in lines:
        finding = parse_line(
            line, scan_id=scan_id, rules=rules, template_source=template_source
        )
        if finding is not None:
            yield finding

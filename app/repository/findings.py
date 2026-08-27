"""findings 저장. SQL 은 이 계층 전용."""
from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable
from types import TracebackType

from app.domain.models import Finding

_COLUMNS = (
    "finding_id", "scan_id", "fingerprint", "source", "template_id",
    "template_source", "matcher_name", "target_raw", "target_scheme",
    "target_host", "target_port", "target_path", "name", "description",
    "vuln_type", "severity", "severity_guide", "cve_ids", "cwe_ids",
    "cvss_score", "cvss_vector", "component_type", "component_slug",
    "ev_request", "ev_response", "ev_extracted", "ev_curl", "status",
    "detected_at",
)

# ON CONFLICT 대상을 (scan_id, fingerprint) 로 한정.
# INSERT OR IGNORE 는 FK·CHECK 위반까지 함께 삼켜 잘못된 데이터가 조용히 사라짐
_INSERT = (
    f"INSERT INTO findings ({', '.join(_COLUMNS)}) "
    f"VALUES ({', '.join('?' * len(_COLUMNS))}) "
    "ON CONFLICT (scan_id, fingerprint) DO NOTHING"
)


def _json(values: list[str]) -> str | None:
    return json.dumps(values, ensure_ascii=False) if values else None


def to_row(finding: Finding) -> tuple:
    target, evidence = finding.target, finding.evidence
    return (
        finding.finding_id,
        finding.scan_id,
        finding.fingerprint,
        finding.source,
        finding.template_id,
        finding.template_source.value,
        finding.matcher_name,
        target.raw,
        target.scheme,
        target.host,
        target.port,
        target.path,
        finding.name,
        finding.description,
        finding.vuln_type.value,
        finding.severity.value,
        finding.severity_guide.value,
        _json(finding.cve_ids),
        _json(finding.cwe_ids),
        finding.cvss_score,
        finding.cvss_vector,
        finding.component_type,
        finding.component_slug,
        evidence.request,
        evidence.response,
        _json(evidence.extracted_values),
        evidence.curl_command,
        finding.status.value,
        finding.detected_at.isoformat(),
    )


def insert_findings(conn: sqlite3.Connection, findings: Iterable[Finding]) -> int:
    """저장된 건수 반환. 중복 fingerprint 는 제외."""
    inserted = 0
    for finding in findings:
        inserted += conn.execute(_INSERT, to_row(finding)).rowcount
    conn.commit()
    return inserted


def count_by_scan(conn: sqlite3.Connection, scan_id: str) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]


class FindingBatchWriter:
    """스캔 중 스트림 저장.

    100건 또는 1초 단위 커밋 (docs/02 §5.3). 커밋 주기를 두는 이유는 두 가지.
    건당 커밋은 느리고, 전량 후 커밋은 중단 시 전체 소실
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        batch_size: int = 100,
        interval_sec: float = 1.0,
    ) -> None:
        self._conn = conn
        self._batch_size = batch_size
        self._interval_sec = interval_sec
        self._pending = 0
        self._last_commit = time.monotonic()
        self.inserted = 0
        self.skipped = 0

    def add(self, finding: Finding) -> None:
        changed = self._conn.execute(_INSERT, to_row(finding)).rowcount
        if changed:
            self.inserted += 1
        else:
            self.skipped += 1  # 중복 fingerprint. nuclei 중복 보고 대응
        self._pending += 1
        if self._pending >= self._batch_size or self._elapsed():
            self.flush()

    def _elapsed(self) -> bool:
        return time.monotonic() - self._last_commit >= self._interval_sec

    def flush(self) -> None:
        if self._pending:
            self._conn.commit()
            self._pending = 0
        self._last_commit = time.monotonic()

    def __enter__(self) -> FindingBatchWriter:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        # 예외로 빠져나갈 때도 커밋. 중단 시 이미 처리된 finding 보존
        self.flush()

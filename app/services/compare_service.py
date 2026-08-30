"""스캔 비교 (docs/00 §4).

도구는 차이만 보고. 조치 성공 여부를 판정하지 않음 - 판정하는 순간
조치 결과에 대한 책임이 도구로 넘어옴 (docs/01 §1.1)

fixed / still_vulnerable 이 아니라 resolved / persisted 를 사용. 명명 규칙 변경 금지
"""
from __future__ import annotations

import sqlite3
from typing import Any

from app.domain.enums import CompareState
from app.repository import environment as env_repo
from app.repository import scans as scan_repo
from app.services.scan_service import ScanError

DISCLAIMER = (
    "미탐지는 조치 완료를 보장하지 않습니다. "
    "진단 조건, 대상 환경의 변화, 탐지 조건의 한계로 인해 탐지되지 않았을 수 있으며, "
    "실제 조치 여부는 담당자의 확인이 필요합니다."
)


def compare(
    conn: sqlite3.Connection, base_id: str, target_id: str
) -> dict[str, Any]:
    """fingerprint 일치로 3분류. fingerprint 는 쿼리스트링을 제외한 경로 기준이라
    파라미터 차이가 오분류를 유발하지 않음 (docs/02 §3.3)
    """
    base = scan_repo.get_scan(conn, base_id)
    target = scan_repo.get_scan(conn, target_id)
    for scan_id, scan in ((base_id, base), (target_id, target)):
        if scan is None:
            raise ScanError(
                "NOT_FOUND", f"스캔 없음: {scan_id}", status_code=404
            )
    if base_id == target_id:
        raise ScanError("INVALID_REQUEST", "같은 스캔끼리는 비교 불가")

    base_rows = _by_fingerprint(conn, base_id)
    target_rows = _by_fingerprint(conn, target_id)

    resolved = [
        _entry(row, base_key="base_finding_id")
        for fingerprint, row in sorted(base_rows.items())
        if fingerprint not in target_rows
    ]
    persisted = [
        {
            **_entry(target_rows[fingerprint], base_key="target_finding_id"),
            "base_finding_id": row["finding_id"],
        }
        for fingerprint, row in sorted(base_rows.items())
        if fingerprint in target_rows
    ]
    emerged = [
        _entry(row, base_key="target_finding_id")
        for fingerprint, row in sorted(target_rows.items())
        if fingerprint not in base_rows
    ]

    return {
        "base_scan": _scan_view(base, len(base_rows)),
        "target_scan": _scan_view(target, len(target_rows)),
        "summary": {
            CompareState.RESOLVED.value: len(resolved),
            CompareState.PERSISTED.value: len(persisted),
            CompareState.EMERGED.value: len(emerged),
        },
        CompareState.RESOLVED.value: resolved,
        CompareState.PERSISTED.value: persisted,
        CompareState.EMERGED.value: emerged,
        "environment_diff": environment_diff(conn, base_id, target_id),
        # 항상 포함. 이 문장이 없으면 미탐지가 조치 완료로 읽힘
        "disclaimer": DISCLAIMER,
    }


def _by_fingerprint(
    conn: sqlite3.Connection, scan_id: str
) -> dict[str, dict[str, Any]]:
    """오탐은 비교 대상에서 제외. 집계에서 빠진 항목이 비교에 나오면 혼란"""
    return {
        row["fingerprint"]: dict(row)
        for row in conn.execute(
            "SELECT finding_id, fingerprint, name, severity, target_host,"
            " template_id FROM findings"
            " WHERE scan_id = ? AND status <> 'false_positive'"
            " ORDER BY fingerprint",
            (scan_id,),
        )
    }


def _entry(row: dict[str, Any], *, base_key: str) -> dict[str, Any]:
    return {
        "fingerprint": row["fingerprint"],
        "name": row["name"],
        "severity": row["severity"],
        "target_host": row["target_host"],
        "template_id": row["template_id"],
        base_key: row["finding_id"],
    }


def _scan_view(scan: dict[str, Any], total: int) -> dict[str, Any]:
    return {
        "scan_id": scan["scan_id"],
        "scanned_at": scan.get("started_at") or scan.get("created_at"),
        "targets": scan.get("targets") or [],
        "total": total,
    }


def environment_diff(
    conn: sqlite3.Connection, base_id: str, target_id: str
) -> dict[str, list[dict[str, Any]]]:
    """환경 변화. 결과 차이의 설명을 제공 (docs/00 §4)"""
    before = _flatten(env_repo.profiles(conn, base_id))
    after = _flatten(env_repo.profiles(conn, target_id))

    changed = [
        {"key": key, "before": before[key], "after": after[key]}
        for key in sorted(before.keys() & after.keys())
        if before[key] != after[key]
    ]
    return {
        "changed": changed,
        "added": [
            {"key": key, "after": after[key]}
            for key in sorted(after.keys() - before.keys())
        ],
        "removed": [
            {"key": key, "before": before[key]}
            for key in sorted(before.keys() - after.keys())
        ],
    }


def _flatten(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    """'application.version' / 'components.<slug>.version' 형태로 평탄화"""
    out: dict[str, Any] = {}
    for profile in profiles:
        for field in ("web_server", "language", "application"):
            item = profile.get(field) or {}
            if item.get("product"):
                out[f"{field}.product"] = item["product"]
                out[f"{field}.version"] = item.get("version")
        for component in profile.get("components") or []:
            out[f"components.{component['slug']}.version"] = component.get("version")
        for exposure in profile.get("exposures") or []:
            out[f"exposures.{exposure['key']}"] = exposure["value"]
    return out

"""템플릿 실행 범위 결정·기록. SQL 은 repository, 판단은 domain (docs/01 §2.1)"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from app.domain import template_exclusion as te
from app.repository import environment as env_repo
from app.repository import settings_repo
from app.repository import templates as template_repo


def enumerator_exclusions(conn: sqlite3.Connection, mode: str) -> list[str]:
    """explicit 은 사용자 지정 그대로. 나머지는 opt-in 이 아니면 열거 2개 제외"""
    if mode == "explicit" or settings_repo.wp_full_enumeration(conn):
        return []
    return list(te.ENUMERATOR_IDS)


def load_metas(conn: sqlite3.Connection) -> list[te.TemplateMeta]:
    return [
        te.TemplateMeta(
            r["template_id"],
            r["file_path"],
            r["source"],
            tuple(r["tags"]),
            r["platform"],
        )
        for r in template_repo.all_meta(conn)
    ]


def prepass_files(metas: Sequence[te.TemplateMeta]) -> list[str]:
    """사전 패스 목록. 색인에만 있고 파일이 사라진 항목은 nuclei 오류라 제외"""
    return sorted(
        m.file_path for m in metas if te.is_prepass(m) and Path(m.file_path).is_file()
    )


def write_list(paths: list[str], directory: Path, name: str) -> Path:
    target = directory / name
    target.write_text("\n".join(paths) + "\n", encoding="utf-8")
    return target


def basis(
    conn: sqlite3.Connection,
    *,
    mode: str,
    excluded_ids: list[str],
    plan: te.ExclusionPlan | None = None,
    prepass: int = 0,
    total_run: int | None = None,
    detected: Sequence[str] = (),
    fallback_reason: str | None = None,
) -> dict[str, Any]:
    """scans.selection_basis. 보고서 A-2 '템플릿 실행 범위' 의 유일한 근거"""
    available = env_repo.local_template_count(conn)
    if total_run is None and mode == "full_scan":
        # 색인에 없는 열거 템플릿까지 빼면 실행 수가 실제보다 작게 기록됨
        present = sum(1 for tid in excluded_ids if template_repo.get(conn, tid))
        total_run = max(available - present, 0)
    return {
        "mode": mode,
        "universe": "environment_filtered"
        if plan and plan.excluded
        else "all_templates",
        "total_available": available,
        "total_run": total_run,
        "excluded_enumerators": list(excluded_ids),
        "wp_full_enumeration": settings_repo.wp_full_enumeration(conn),
        "excluded": plan.by_platform() if plan else [],
        "fallback_reason": fallback_reason or (plan.fallback_reason if plan else None),
        "detected": sorted(detected),
        "prepass_templates": prepass,
    }

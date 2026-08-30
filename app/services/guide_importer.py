"""가이드 본문 임포트 (docs/03 §2.3).

본문은 저작권 대상이라 저장소에 없다. 사용자가 파일을 받아 직접 넣음 (절대규칙 8).
전체 삭제 후 재적재하며 finding_guide_refs 는 건드리지 않음 - 별도 층이고
본문 없이도 매핑 결과가 유지되어야 함
"""
from __future__ import annotations

import csv
import io
import logging
import sqlite3
from pathlib import Path
from typing import Any

from app.repository import guide as guide_repo
from app.repository import settings_repo

logger = logging.getLogger(__name__)

# case_text 는 항목당 최대 8,675자. 기본 한도(131,072)로 충분하나 여유를 둠
_FIELD_LIMIT = 1_000_000

_REQUIRED_COLUMNS = ("item_code", "item_name", "guide_version")
_IMAGE_COLUMNS = ("item_code", "file_path")


class ImportError_(ValueError):
    """임포트 실패. 어느 파일의 무엇이 문제인지 담음"""

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.errors = errors or []


def read_rows(text: str) -> list[dict[str, str]]:
    csv.field_size_limit(_FIELD_LIMIT)
    return list(csv.DictReader(io.StringIO(text)))


def import_text(
    conn: sqlite3.Connection,
    items_csv: str,
    images_csv: str | None = None,
) -> dict[str, Any]:
    """CSV 문자열 임포트. 업로드·CLI 양쪽이 이 경로를 사용"""
    rows = read_rows(items_csv)
    if not rows:
        raise ImportError_("본문 CSV 비어 있음")

    missing = [c for c in _REQUIRED_COLUMNS if c not in rows[0]]
    if missing:
        raise ImportError_(f"필수 컬럼 누락: {missing}")

    errors: list[str] = []
    codes = {row["item_code"] for row in rows}
    versions = sorted({(row.get("guide_version") or "").strip() for row in rows})
    if len(versions) > 1:
        # 판 섞임은 보고서 근거 페이지가 어긋나는 원인임
        errors.append(f"guide_version 이 섞여 있음: {versions}")

    item_count = guide_repo.replace_items(conn, rows)

    image_count = 0
    if images_csv:
        images = read_rows(images_csv)
        missing = [c for c in _IMAGE_COLUMNS if images and c not in images[0]]
        if missing:
            raise ImportError_(f"이미지 CSV 필수 컬럼 누락: {missing}")
        orphans = sorted({r["item_code"] for r in images} - codes)
        if orphans:
            errors.append(f"본문 없는 이미지 항목 {len(orphans)}건: {orphans[:5]}")
            images = [r for r in images if r["item_code"] in codes]
        image_count = guide_repo.replace_images(conn, images)

    fts = guide_repo.rebuild_fts(conn)
    version = versions[-1] if versions else None
    if version:
        settings_repo.put_many(conn, {"guide_version": version})
    conn.commit()

    logger.info("가이드 임포트: 항목 %s · 이미지 %s · FTS %s", item_count, image_count, fts)
    return {
        "imported": item_count > 0,
        "version": version,
        "item_count": item_count,
        "image_count": image_count,
        "skipped": 0,
        "errors": errors,
    }


def import_files(
    conn: sqlite3.Connection,
    items_path: Path,
    images_path: Path | None = None,
) -> dict[str, Any]:
    if not items_path.is_file():
        raise ImportError_(f"파일 없음: {items_path}")
    images = None
    if images_path:
        if not images_path.is_file():
            raise ImportError_(f"파일 없음: {images_path}")
        images = images_path.read_text(encoding="utf-8-sig")
    return import_text(
        conn, items_path.read_text(encoding="utf-8-sig"), images
    )

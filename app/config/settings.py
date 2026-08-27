"""파일·환경 수준 설정.

런타임 플래그(offline_mode / llm_enabled / target_allowlist)의 원본은
DB settings 테이블 (db/schema.sql §8). 여기에는 DB 접속 전 필요한 값만.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _path(env: str, default: Path) -> Path:
    override = os.environ.get(env)
    return Path(override).expanduser().resolve() if override else default


DB_PATH = _path("REDAR_DB", ROOT / "redar.db")
DATA_DIR = _path("REDAR_DATA_DIR", ROOT / "data")
SCHEMA_PATH = ROOT / "db" / "schema.sql"
MIGRATIONS_DIR = ROOT / "db" / "migrations"
FONTS_DIR = ROOT / "assets" / "fonts"


def nuclei_bin() -> str | None:
    """nuclei 실행 파일 경로. 미설치 시 None (docs/01 §5.5)."""
    return os.environ.get("REDAR_NUCLEI") or shutil.which("nuclei")

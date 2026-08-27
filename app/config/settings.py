"""파일·환경 수준 설정.

런타임 플래그(offline_mode / llm_enabled / target_allowlist ...)는 여기가 아니라
DB 의 settings 테이블이 원본이다 (db/schema.sql §8). 두 곳에 두면 어긋난다.
여기에는 DB 를 열기 전에 알아야 하는 값만 둔다.
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
    """nuclei 실행 파일 경로. 없으면 None (docs/01 §5.5)."""
    return os.environ.get("REDAR_NUCLEI") or shutil.which("nuclei")

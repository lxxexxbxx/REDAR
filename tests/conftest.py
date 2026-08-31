"""테스트 공통 픽스처.

DB 경로를 임시 디렉터리로 전환. settings 가 임포트 시점에 환경변수를 읽으므로
app 임포트보다 먼저 설정 필요
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["REDAR_DB"] = str(Path(tempfile.mkdtemp(prefix="redar-test-")) / "redar.db")

import pytest  # noqa: E402

from app.cli import init_db  # noqa: E402
from app.config import settings  # noqa: E402
from app.repository.db import session  # noqa: E402


@pytest.fixture(scope="session")
def db_path() -> Path:
    # load_guide=False: 본문 미탑재가 정상 상태임을 검증하는 테스트가 다수 (절대규칙 3).
    # 번들 본문 자동 적재는 test_data_csv 가 따로 검증
    init_db(load_guide=False)
    return settings.DB_PATH


@pytest.fixture
def conn(db_path: Path):
    with session(db_path) as c:
        yield c

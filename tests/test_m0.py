"""M0 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M0)."""
from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.config import settings

# FTS5 내부 테이블 5개와 sqlite_sequence 만 제외한다.
# '_fts%' 로 뭉뚱그리면 본체까지 빠져 18개가 나온다.
# 주의: 파이썬 raw 문자열이어야 한다. "ESCAPE '\'" 는 \' 가 따옴표로 해석되어
#       ESCAPE '' (빈 문자열) 이 되고 SQLite 가 거부한다.
COUNT_TABLES = r"""
SELECT COUNT(*) FROM sqlite_master
WHERE type='table'
  AND name NOT LIKE 'guide_items_fts\_%' ESCAPE '\'
  AND name <> 'sqlite_sequence'
"""


def test_schema_object_counts(conn):
    assert conn.execute(COUNT_TABLES).fetchone()[0] == 19
    assert conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='view'"
    ).fetchone()[0] == 5


@pytest.mark.parametrize(
    "table,expected",
    [
        ("vuln_type_rules", 129),
        ("guide_mappings", 454),          # guide_mappings.csv 135 + templates 319
        ("component_advisories", 951),
    ],
)
def test_bundled_csv_loaded(conn, table, expected):
    assert conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == expected


def test_guide_items_empty(conn):
    """가이드 본문은 저작권 대상이라 적재하지 않는다. 비어 있는 것이 정상."""
    assert conn.execute("SELECT COUNT(*) FROM guide_items").fetchone()[0] == 0


def test_guide_coverage_view(conn):
    row = conn.execute("SELECT * FROM v_guide_coverage").fetchone()
    assert (row["items_total"], row["items_covered"]) == (0, 36)


def test_foreign_keys_enforced(conn):
    """PRAGMA foreign_keys 를 빠뜨리면 이 INSERT 가 조용히 성공한다."""
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO findings (finding_id, scan_id, fingerprint, template_id,"
            " target_raw, target_host, name, severity, severity_guide)"
            " VALUES ('fnd_x', 'scn_missing', 'fp', 'tpl', 'http://h', 'h',"
            " 'n', 'high', '상')"
        )


def test_init_db_is_idempotent(db_path):
    from app.cli import init_db
    from app.repository.db import session

    init_db(db_path)
    with session(db_path) as c:
        assert c.execute("SELECT COUNT(*) FROM guide_mappings").fetchone()[0] == 454


def test_health(db_path):
    from app.main import app

    body = TestClient(app).get("/api/v1/health").json()
    assert body["status"] == "ok"
    assert body["db"] == "connected"
    assert set(body) == {"status", "db", "nuclei"}


@pytest.mark.parametrize(
    "font", ["NanumGothic.woff2", "NanumGothicBold.woff2", "D2Coding.woff2"]
)
def test_font_covers_all_hangul_syllables(font):
    """한글 음절 11,172자 전부. 누락을 M7 에서 발견하면 이미 늦다 (docs/04 §6)."""
    ttLib = pytest.importorskip("fontTools.ttLib")
    cmap = ttLib.TTFont(settings.FONTS_DIR / font).getBestCmap()
    assert sum(1 for c in cmap if 0xAC00 <= c <= 0xD7A3) == 11172


def test_font_license_present():
    assert (settings.FONTS_DIR / "LICENSE-OFL.txt").is_file()

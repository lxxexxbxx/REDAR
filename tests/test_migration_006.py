"""마이그레이션 006. scans 재구성 중 하위 행이 사라지면 과거 스캔 전부 소실"""
from __future__ import annotations

import sqlite3

from app.cli import init_db
from app.config import settings

_OLD_CHECK = "CHECK (selection_mode IN ('explicit','filter','environment_driven'))"
_NEW_CHECK = "CHECK (selection_mode IN ('explicit','filter','environment_driven','full_scan'))"


def _v05_db(path) -> None:
    """006 직전 형태. 현재 schema.sql 에서 CHECK 만 옛 값으로 되돌림"""
    schema = settings.SCHEMA_PATH.read_text(encoding="utf-8")
    assert _NEW_CHECK in schema
    raw = sqlite3.connect(path)
    raw.executescript(schema.replace(_NEW_CHECK, _OLD_CHECK))
    raw.execute("DELETE FROM schema_version WHERE version = 6")
    raw.execute("INSERT INTO scans (scan_id, status, selection_mode)"
                " VALUES ('scn_old', 'completed', 'filter')")
    raw.execute("INSERT INTO scan_targets (scan_id, raw, host)"
                " VALUES ('scn_old', 'http://a', 'a')")
    raw.execute(
        "INSERT INTO findings (finding_id, scan_id, fingerprint, template_id, target_raw,"
        " target_host, name, severity, severity_guide)"
        " VALUES ('fnd_old', 'scn_old', 'fp', 't', 'http://a', 'a', 'n', 'high', '상')"
    )
    raw.commit()
    raw.close()


def test_migration_006_allows_full_scan_and_keeps_children(tmp_path):
    db = tmp_path / "v05.db"
    _v05_db(db)
    init_db(db_path=db, load_guide=False)

    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("INSERT INTO scans (scan_id, status, selection_mode)"
                 " VALUES ('scn_new', 'queued', 'full_scan')")
    # 재구성 전 하위 행 보존 (DROP 연쇄 삭제 방지 검증)
    assert conn.execute(
        "SELECT COUNT(*) FROM scan_targets WHERE scan_id = 'scn_old'").fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id = 'scn_old'").fetchone()[0] == 1
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert conn.execute(
        "SELECT cnt_total FROM v_scan_summary WHERE scan_id = 'scn_old'").fetchone()[0] == 1
    assert 6 in {r[0] for r in conn.execute("SELECT version FROM schema_version")}
    # FK 가 다시 켜진 상태로 새 테이블에 연결됐는지
    conn.execute("DELETE FROM scans WHERE scan_id = 'scn_old'")
    assert conn.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id = 'scn_old'").fetchone()[0] == 0
    conn.close()

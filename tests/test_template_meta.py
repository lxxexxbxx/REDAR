"""색인 표지 산출. 제외 계산의 입력이므로 틀리면 미탐지로 이어짐"""

from __future__ import annotations

import sqlite3

from app.domain import template_meta as tm


def test_framework_wins_over_product():
    assert (
        tm.platform_of({"framework": "wordpress", "product": "tourfic"}, [])
        == "wordpress"
    )


def test_wordpress_tags_imply_platform():
    assert tm.platform_of({}, ["wp-plugin", "cve"]) == "wordpress"


def test_product_is_fallback_and_lowercased():
    assert tm.platform_of({"product": "HTTP_Server"}, ["apache"]) == "http_server"


def test_escaped_and_dash_framework_ignored():
    assert tm.platform_of({"framework": "joomla\\!"}, []) == "joomla!"
    assert tm.platform_of({"framework": "-"}, []) is None


def test_no_marker_is_none():
    assert tm.platform_of({}, ["exposure"]) is None


def test_wp_slug_from_namespace():
    assert (
        tm.wp_component_slug({"plugin_namespace": "ad-inserter"}, ["wp-plugin"], "")
        == "ad-inserter"
    )


def test_wp_slug_from_request_path_when_namespace_missing():
    raw = 'path:\n  - "{{BaseURL}}/wp-content/plugins/user-registration/readme.txt"'
    assert tm.wp_component_slug({}, ["wp-plugin"], raw) == "user-registration"


def test_wp_slug_requires_wp_tag():
    assert tm.wp_component_slug({"plugin_namespace": "x"}, ["tech"], "") is None


def test_migration_adds_platform_to_existing_db(tmp_path):
    """기존 DB 는 CREATE IF NOT EXISTS 로 컬럼이 안 생김. 005 가 추가해야 함"""
    from app.cli import init_db

    db = tmp_path / "old.db"
    raw = sqlite3.connect(db)
    raw.executescript(
        "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);"
        "INSERT INTO schema_version VALUES (1),(2),(3),(4);"
        # schema.sql 의 인덱스·뷰가 참조하는 컬럼은 둠. platform 만 없는 v0.4 DB 재현
        "CREATE TABLE templates (template_id TEXT PRIMARY KEY, source TEXT NOT NULL,"
        " file_path TEXT NOT NULL, name TEXT NOT NULL, description TEXT, severity TEXT,"
        " vuln_type TEXT, cve_ids TEXT, cwe_ids TEXT, tags TEXT, cvss_score REAL,"
        " cvss_vector TEXT, fixed_version TEXT, is_detection INTEGER NOT NULL DEFAULT 0,"
        " component_slugs TEXT, form_json TEXT, yaml_hash TEXT,"
        " created_at TEXT, updated_at TEXT);"
    )
    raw.commit()
    raw.close()
    init_db(db_path=db, load_guide=False)
    cols = {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(templates)")}
    assert "platform" in cols


def test_index_stores_platform_and_slug(conn, tmp_path, monkeypatch):
    from app.config import settings
    from app.repository import templates as repo
    from app.services import template_service

    official = tmp_path / "official" / "http" / "cves"
    official.mkdir(parents=True)
    (official / "a.yaml").write_text(
        "id: redar-t-a\ninfo:\n  name: a\n  severity: high\n"
        "  metadata:\n    framework: wordpress\n  tags: cve\n",
        encoding="utf-8",
    )
    (official / "b.yaml").write_text(
        "id: redar-t-b\ninfo:\n  name: b\n  severity: info\n"
        "  metadata:\n    plugin_namespace: give\n  tags: tech,wordpress,wp-plugin\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "OFFICIAL_DIR", tmp_path / "official")
    monkeypatch.setattr(settings, "CUSTOM_DIR", tmp_path / "custom")
    try:
        template_service.index_all(conn)
        assert repo.get(conn, "redar-t-a")["platform"] == "wordpress"
        b = repo.get(conn, "redar-t-b")
        assert (b["platform"], b["component_slugs"]) == ("wordpress", "give")
    finally:
        conn.execute("DELETE FROM templates WHERE template_id LIKE 'redar-t-%'")
        conn.commit()

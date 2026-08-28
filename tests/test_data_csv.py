"""SQLite 초기 데이터는 data/*.csv 에서만 들어온다.

코드·SQL 에 값을 두면 DB 의 값이 어디서 왔는지 추적할 수 없고 재적재 경로가 갈라진다
"""
from __future__ import annotations

import csv
import importlib.util
import re
import sqlite3
import sys

import pytest

from app.cli import _CSV_LOADS, init_db, load_data
from app.config import settings
from app.repository import settings_repo
from app.repository.db import session

ROOT = settings.SCHEMA_PATH.parents[1]

# schema_version 은 마이그레이션 장부이며 데이터가 아니다
_ALLOWED_SEED_TABLES = {"schema_version"}


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "build_data_csv", ROOT / "tools" / "build_data_csv.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["build_data_csv"] = module
    spec.loader.exec_module(module)
    return module


def _read(name: str) -> list[dict[str, str]]:
    with (settings.DATA_DIR / name).open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def _fresh_db(tmp_path):
    db = tmp_path / "redar.db"
    init_db(db)
    return db


def test_schema_sql_has_no_seed_data():
    """스키마 파일에 초기 데이터를 두면 CSV 와 값이 갈라진다"""
    sql = settings.SCHEMA_PATH.read_text(encoding="utf-8")
    tables = set(re.findall(r"INSERT\s+(?:OR\s+\w+\s+)?INTO\s+(\w+)", sql, re.I))
    assert tables <= _ALLOWED_SEED_TABLES, f"SQL 하드코딩 초기 데이터: {tables}"


def test_settings_defaults_come_from_csv(tmp_path):
    rows = _read("settings_defaults.csv")
    with session(_fresh_db(tmp_path)) as conn:
        stored = settings_repo.get_all(conn)
    assert stored == {r["key"]: r["value"] for r in rows}


def test_allowlist_default_blocks_everything(tmp_path):
    """기본값은 전부 차단 (절대규칙 6). CSV 로 옮긴 뒤에도 유지되어야 함"""
    with session(_fresh_db(tmp_path)) as conn:
        assert settings_repo.target_allowlist(conn) == []
        assert settings_repo.offline_mode(conn) is True


def test_reload_keeps_user_edited_settings(tmp_path):
    """CSV 재적재가 사용자가 바꾼 값을 기본값으로 되돌리면 안 됨"""
    db = _fresh_db(tmp_path)
    with session(db) as conn:
        settings_repo.put_many(conn, {"target_allowlist": ["10.0.0.1"]})
        load_data(conn)
        assert settings_repo.target_allowlist(conn) == ["10.0.0.1"]


def test_reload_is_idempotent(tmp_path):
    db = _fresh_db(tmp_path)
    with session(db) as conn:
        before = load_data(conn)
        load_data(conn)
        totals = {
            t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in ("vuln_type_rules", "guide_mappings", "component_advisories")
        }
    assert before["guide_mappings.csv"] == 135
    assert totals == {
        "vuln_type_rules": 129, "guide_mappings": 454, "component_advisories": 951,
    }


def test_unknown_column_is_rejected(tmp_path):
    """오타 컬럼을 조용히 버리면 값이 누락된 채 적재가 성공한다"""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    for load in _CSV_LOADS:
        (data_dir / load.filename).write_text(
            (settings.DATA_DIR / load.filename).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    target = data_dir / "vuln_type_rules.csv"
    lines = target.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("vuln_type", "vuln_typo")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with session(_fresh_db(tmp_path)) as conn:
        with pytest.raises(ValueError, match="vuln_typo"):
            load_data(conn, data_dir)


def test_missing_csv_is_not_silent(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with session(_fresh_db(tmp_path)) as conn:
        with pytest.raises(FileNotFoundError):
            load_data(conn, empty)


def test_note_column_is_allowed():
    """CSV 에 유지보수용 주석 컬럼을 둘 수 있어야 한다. 없으면 근거가 코드로 새어나감"""
    assert "note" in _read("settings_defaults.csv")[0]


def test_bundled_csv_passes_tool_validation(capsys):
    """tools/build_data_csv.py 의 검증을 CI 에서 그대로 돌린다"""
    _load_tool().validate(settings.DATA_DIR, None)
    assert "검증 통과" in capsys.readouterr().out


def test_vuln_type_values_are_enum_members():
    from app.domain.enums import VulnType

    values = {v.value for v in VulnType}
    assert {r["vuln_type"] for r in _read("vuln_type_rules.csv")} <= values


def test_external_endpoint_keys_are_code_controlled():
    """통신 지점 목록은 코드가 통제한다. CSV 로 4번째 지점을 추가할 수 없어야 함 (절대규칙 5)"""
    assert settings_repo.EXTERNAL_ENDPOINT_KEYS == (
        "template_sync", "llm_api", "cve_lookup"
    )
    csv_keys = {r["key"] for r in _read("settings_defaults.csv")}
    extra = {k for k in csv_keys if k.startswith("ext_") and k.endswith("_url")}
    assert extra == {"ext_template_sync_url"}


def test_derived_csv_regenerates_without_hardcoded_values():
    """도구가 매핑 값을 상수로 들고 있으면 CSV 와 코드 두 곳에 값이 생긴다"""
    source = (ROOT / "tools" / "build_data_csv.py").read_text(encoding="utf-8")
    for symbol in ("CWE_VT", "TAG_VT", "CWE_GUIDE", "EXPOSURE_GUIDE", "VT_GUIDE"):
        assert f"{symbol} = " not in source, f"{symbol} 하드코딩 잔존"


def test_in_memory_schema_load_matches_file_db(tmp_path):
    """도구가 쓰는 in-memory 검증 경로와 실제 init-db 결과가 같아야 한다"""
    memory = sqlite3.connect(":memory:")
    memory.row_factory = sqlite3.Row
    memory.executescript(settings.SCHEMA_PATH.read_text(encoding="utf-8"))
    load_data(memory)

    with session(_fresh_db(tmp_path)) as conn:
        for table in ("settings", "vuln_type_rules", "guide_mappings",
                      "component_advisories"):
            assert (
                memory.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                == conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            )
    memory.close()


# ────────────────────────────────────────────── 가이드 임포트 (절대규칙 3·8)

_GUIDE_ITEMS_HEADER = (
    "item_code,item_code_raw,item_name,category,section,severity_guide,"
    "check_content,check_purpose,security_threat,reference_note,target,"
    "criteria_safe,criteria_vuln,remediation,impact,detail,case_text,reference,"
    "page_start,page_end,guide_version"
)


def _write_guide(tmp_path, codes=("WA-01", "WEB-25"), version="2026"):
    items = tmp_path / "guide_items_test.csv"
    lines = [_GUIDE_ITEMS_HEADER]
    for i, code in enumerate(codes, start=1):
        lines.append(
            f"{code},{code},항목 {code},웹 서비스,WEB > 1,상,"
            f"점검 내용 {code},목적,위협,참고,대상,양호,취약,조치,영향,상세,"
            f"사례 본문 {code},출처,{i},{i},{version}"
        )
    items.write_text("\n".join(lines) + "\n", encoding="utf-8")

    images = tmp_path / "guide_images_test.csv"
    images.write_text(
        "item_code,file_path,page,caption,sort_order\n"
        + "".join(f"{c},/abs/{c}_01.png,{i},캡션,1\n" for i, c in enumerate(codes, 1)),
        encoding="utf-8",
    )
    return items, images


def test_import_guide_fills_items_images_and_fts(tmp_path):
    from app.cli import import_guide

    db = _fresh_db(tmp_path)
    items, images = _write_guide(tmp_path)
    result = import_guide(items, images, db)

    # 반환 형식은 docs/00 §6 의 POST /guide/import 응답과 동일하다
    assert result["imported"] is True
    assert (result["item_count"], result["image_count"]) == (2, 2)
    assert result["errors"] == []
    with session(db) as conn:
        status = __import__(
            "app.repository.guide", fromlist=["status"]
        ).status(conn)
        assert status["imported"] is True
        assert status["item_count"] == 2
        assert status["version"] == "2026"
        # FTS 는 트리거가 없어 임포터가 채운다. 누락 시 조용히 0건
        hit = conn.execute(
            "SELECT item_code FROM guide_items_fts WHERE guide_items_fts MATCH '사례'"
        ).fetchall()
        assert len(hit) == 2


def test_import_guide_is_idempotent(tmp_path):
    """재임포트가 이미지를 두 배로 늘리면 안 됨. guide_item_images 에 UNIQUE 가 없다"""
    from app.cli import import_guide

    db = _fresh_db(tmp_path)
    items, images = _write_guide(tmp_path)
    import_guide(items, images, db)
    import_guide(items, images, db)

    with session(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM guide_items").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM guide_item_images").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM guide_items_fts").fetchone()[0] == 2


def test_import_guide_sets_settings_version(tmp_path):
    from app.cli import import_guide

    db = _fresh_db(tmp_path)
    items, _ = _write_guide(tmp_path, version="2027")
    import_guide(items, None, db)
    with session(db) as conn:
        assert settings_repo.get_all(conn)["guide_version"] == "2027"


def test_import_guide_requires_existing_db(tmp_path):
    from app.cli import import_guide

    items, _ = _write_guide(tmp_path)
    with pytest.raises(FileNotFoundError):
        import_guide(items, None, tmp_path / "nope.db")


def test_part_a_works_without_guide(tmp_path):
    """가이드 미탑재가 정상 상태여야 한다 (절대규칙 3)"""
    from app.repository import guide as guide_repo

    with session(_fresh_db(tmp_path)) as conn:
        status = guide_repo.status(conn)
    assert status["imported"] is False
    assert status["mapping_count"] == 454      # 매핑은 번들이라 항상 존재
    # 본문 없이도 커버리지 고지는 나온다. 단 "382개 중" 대신 미탑재를 명시 (절대규칙 10)
    notice = status["coverage_notice"]
    assert "36개" in notice and "미탑재" in notice
    assert "탐지되지 않음이 양호를 의미하지 않습니다" in notice


def test_guide_body_is_never_committed():
    """가이드 본문·이미지는 저작권 대상. 저장소에 들어가면 안 된다 (절대규칙 8)"""
    import subprocess

    tracked = subprocess.run(
        ["git", "ls-files", "data/"], capture_output=True, text=True, cwd=ROOT
    ).stdout.split()
    leaked = [f for f in tracked if "guide_items" in f or "guide_images" in f]
    assert not leaked, f"저작권 데이터 추적됨: {leaked}"

"""REDAR CLI.

    python -m app.cli init-db
    python -m app.cli load-data          # data/*.csv 재적재
"""
from __future__ import annotations

import argparse
import csv
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from app import __version__
from app.config import settings
from app.domain.enums import ScanStatus
from app.domain.ids import new_id
from app.repository import settings_repo
from app.repository.db import session


@dataclass(frozen=True)
class CsvLoad:
    """번들 CSV 1개의 적재 규칙."""

    filename: str
    table: str
    conflict: str | None          # ON CONFLICT 대상. 식 인덱스는 식 그대로. None = 단순 INSERT
    keys: tuple[str, ...] = ()    # 충돌 키. UPDATE 대상에서 제외
    replace: bool = True          # False = 기존 행 유지. 사용자 변경값 보호


# SQLite 초기 데이터는 전부 이 목록의 CSV 에서만 들어온다. 코드·SQL 하드코딩 금지
#
# settings 만 replace=False: 재적재가 사용자가 바꾼 allowlist·오프라인 모드를
# 기본값으로 되돌리면 안 됨
#
# component_advisories 충돌 대상이 식(COALESCE)인 이유: uq_advisory 가 식 인덱스이므로
# 컬럼 목록으로는 매칭 불가 (db/schema.sql §4)
#
# guide_mappings 는 CSV 2개가 동일 테이블 적재 (docs/05 §1.2)
_CSV_LOADS: tuple[CsvLoad, ...] = (
    CsvLoad("settings_defaults.csv", "settings", "key", ("key",), replace=False),
    CsvLoad(
        "vuln_type_rules.csv", "vuln_type_rules",
        "match_type, match_value", ("match_type", "match_value"),
    ),
    CsvLoad(
        "guide_mappings.csv", "guide_mappings",
        "match_type, match_value, item_code",
        ("match_type", "match_value", "item_code"),
    ),
    CsvLoad(
        "guide_mappings.templates.csv", "guide_mappings",
        "match_type, match_value, item_code",
        ("match_type", "match_value", "item_code"),
    ),
    CsvLoad(
        "component_advisories.csv", "component_advisories",
        "component_type, slug, COALESCE(cve_id,\'\'), COALESCE(template_id,\'\')",
        ("component_type", "slug", "cve_id", "template_id"),
    ),
)

# 유지보수용 주석 컬럼. 테이블에 없어도 오류로 보지 않는다
_NOTE_COLUMNS = frozenset({"note"})


# guide_items(가이드 본문) 미적재. 저작권 대상, 사용자 임포트 (절대규칙 8)


def _upsert_csv(conn: sqlite3.Connection, path: Path, load: CsvLoad) -> int:
    """CSV 1개 적재. 행 수 반환. 파일 부재는 오류."""
    if not path.is_file():
        raise FileNotFoundError(f"번들 CSV 없음: {path}")
    with path.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        return 0

    table_cols = {
        r["name"] for r in conn.execute(f"PRAGMA table_info({load.table})")
    }
    unknown = set(rows[0]) - table_cols - _NOTE_COLUMNS
    if unknown:
        # 오타 컬럼을 조용히 버리면 값이 통째로 누락된 채 적재가 성공한다
        raise ValueError(f"{path.name}: 테이블에 없는 컬럼 {sorted(unknown)}")
    cols = [c for c in rows[0] if c in table_cols]

    sql = (
        f"INSERT INTO {load.table} ({', '.join(cols)}) "
        f"VALUES ({', '.join('?' * len(cols))})"
    )
    if load.conflict:
        updates = [c for c in cols if c not in load.keys]
        action = (
            f"DO UPDATE SET {', '.join(f'{c} = excluded.{c}' for c in updates)}"
            if load.replace and updates
            else "DO NOTHING"
        )
        sql += f" ON CONFLICT ({load.conflict}) {action}"
    # 빈 문자열 -> NULL. 미변환 시 nullable 컬럼에 '없음'이 두 종류로 혼재
    conn.executemany(sql, [[row[c] or None for c in cols] for row in rows])
    return len(rows)


def load_data(conn: sqlite3.Connection, data_dir: Path | None = None) -> dict[str, int]:
    """번들 CSV 전부 적재. 재실행 안전. 초기 데이터의 유일한 입력 경로"""
    source = data_dir or settings.DATA_DIR
    loaded: dict[str, int] = {}
    for load in _CSV_LOADS:
        n = _upsert_csv(conn, source / load.filename, load)
        loaded[load.filename] = n
        print(f"  {load.filename} -> {load.table}: {n} rows")
    conn.commit()
    return loaded


def _apply_migrations(conn: sqlite3.Connection) -> list[int]:
    applied = {r["version"] for r in conn.execute("SELECT version FROM schema_version")}
    done = []
    for f in sorted(settings.MIGRATIONS_DIR.glob("*.sql")):
        version = int(f.name.split("_", 1)[0])
        if version in applied:
            continue
        conn.executescript(f.read_text(encoding="utf-8"))
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
        conn.commit()
        done.append(version)
    return done


def init_db(db_path: Path | None = None, data_dir: Path | None = None) -> None:
    """스키마 적용 -> 미적용 마이그레이션 -> 번들 CSV 적재. 재실행 안전"""
    target = db_path or settings.DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    with session(target) as conn:
        conn.executescript(settings.SCHEMA_PATH.read_text(encoding="utf-8"))
        for version in _apply_migrations(conn):
            print(f"  migration {version:03d} applied")
        load_data(conn, data_dir)
        _print_totals(conn)
    print(f"init-db done: {target}")


def reload_data(db_path: Path | None = None, data_dir: Path | None = None) -> None:
    """기존 DB 에 CSV 재적재. CSV 를 고친 뒤 DB 를 다시 만들지 않고 반영하는 경로"""
    target = db_path or settings.DB_PATH
    if not target.is_file():
        raise FileNotFoundError(f"DB 없음: {target}. init-db 를 먼저 실행")
    with session(target) as conn:
        load_data(conn, data_dir)
        _print_totals(conn)
    print(f"load-data done: {target}")


def _print_totals(conn: sqlite3.Connection) -> None:
    for table in ("settings", "vuln_type_rules", "guide_mappings",
                  "component_advisories"):
        total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"  {table}: {total} rows total")


# 가이드 본문·이미지. 파일명이 배포마다 달라 _CSV_LOADS 에 두지 않고 경로를 받는다
_GUIDE_ITEMS = CsvLoad("guide_items.csv", "guide_items", "item_code", ("item_code",))
_GUIDE_IMAGES = CsvLoad("guide_images.csv", "guide_item_images", None)


def import_guide(
    items_csv: Path,
    images_csv: Path | None = None,
    db_path: Path | None = None,
) -> dict[str, int]:
    """가이드 본문 CSV 임포트. 저작권 대상이라 저장소에 없고 사용자가 직접 넣는다

    본문 없이도 보고서 Part A 는 생성된다 (절대규칙 3). 이 명령은 Part B 를 켜는 경로
    """
    from app.repository import guide as guide_repo

    target = db_path or settings.DB_PATH
    if not target.is_file():
        raise FileNotFoundError(f"DB 없음: {target}. init-db 를 먼저 실행")

    result: dict[str, int] = {}
    with session(target) as conn:
        result["items"] = _upsert_csv(conn, items_csv, _GUIDE_ITEMS)
        print(f"  {items_csv.name} -> guide_items: {result['items']} rows")

        if images_csv:
            codes = _column_values(images_csv, "item_code")
            removed = guide_repo.clear_images(conn, sorted(set(codes)))
            result["images"] = _upsert_csv(conn, images_csv, _GUIDE_IMAGES)
            print(
                f"  {images_csv.name} -> guide_item_images:"
                f" {result['images']} rows (기존 {removed}행 교체)"
            )

        result["fts"] = guide_repo.rebuild_fts(conn)
        print(f"  guide_items_fts 재구축: {result['fts']} rows")

        found = guide_repo.versions(conn)
        if len(found) > 1:
            # 판 섞임은 보고서 근거 페이지가 어긋나는 원인이라 조용히 넘기지 않는다
            print(f"  [경고] guide_version 이 섞여 있음: {found}")
        if found:
            settings_repo.put_many(conn, {"guide_version": found[-1]})
        conn.commit()

        orphans = guide_repo.orphan_image_codes(conn)
        if orphans:
            print(f"  [경고] 본문 없는 이미지 항목: {orphans[:5]}")
        print(f"  guide_version: {found[-1] if found else '없음'}")
    print(f"import-guide done: {target}")
    return result


def _column_values(path: Path, column: str) -> list[str]:
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return [row[column] for row in csv.DictReader(fh)]


def import_scan(
    jsonl_path: Path,
    targets: list[str],
    nuclei_version: str | None = None,
    db_path: Path | None = None,
) -> str:
    """외부에서 실행한 nuclei JSONL 을 스캔으로 적재. 스캔 ID 반환.

    REDAR 가 직접 돌리지 못한 환경(원격 랩 등)의 결과를 가져오는 경로.
    파서·저장 경로는 실제 스캔과 동일하므로 결과 화면·보고서가 그대로 동작
    """
    from app.adapters.nuclei.parser import parse_stream
    from app.repository import scans as scan_repo
    from app.repository.findings import FindingBatchWriter
    from app.repository.rules import load_vuln_type_rules

    scan_id = new_id("scn")
    with session(db_path or settings.DB_PATH) as conn:
        scan_repo.insert_scan(
            conn,
            scan_id=scan_id,
            selection_mode="explicit",
            selection_detail={"imported_from": jsonl_path.name},
            collect_environment=False,
            threads=0,
            timeout_sec=0,
            retries=0,
            rate_limit=None,
            targets=targets,
            tool_version=__version__,
            nuclei_version=nuclei_version,
        )
        rules = load_vuln_type_rules(conn)
        lines = jsonl_path.read_text(encoding="utf-8").splitlines()
        with FindingBatchWriter(conn) as writer:
            for finding in parse_stream(lines, scan_id=scan_id, rules=rules):
                writer.add(finding)
        scan_repo.set_status(conn, scan_id, ScanStatus.COMPLETED)
        print(f"  적재 {writer.inserted}건 / 중복 제외 {writer.skipped}건")
    print(f"import-scan done: {scan_id}")
    return scan_id


def main() -> None:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    initializer = sub.add_parser("init-db", help="스키마 생성 + 번들 CSV 적재")
    initializer.add_argument("--data-dir", type=Path, help="data 디렉터리 경로")

    loader = sub.add_parser(
        "load-data", help="기존 DB 에 data/*.csv 재적재 (CSV 수정 후 반영)"
    )
    loader.add_argument("--data-dir", type=Path, help="data 디렉터리 경로")

    guide = sub.add_parser(
        "import-guide", help="가이드 본문 CSV 적재 (저작권 대상. 사용자가 직접 준비)"
    )
    guide.add_argument("items", type=Path, help="guide_items CSV")
    guide.add_argument("--images", type=Path, help="guide_item_images CSV")

    importer = sub.add_parser(
        "import-scan", help="외부에서 실행한 nuclei JSONL 을 스캔으로 적재"
    )
    importer.add_argument("jsonl", type=Path, help="nuclei -jsonl 출력 파일")
    importer.add_argument(
        "--target", action="append", required=True, help="대상. 여러 번 지정 가능"
    )
    importer.add_argument(
        "--nuclei-version", help="결과를 만든 nuclei 버전. 재현성 기록용"
    )

    args = parser.parse_args()
    if args.command == "init-db":
        init_db(data_dir=args.data_dir)
    elif args.command == "load-data":
        reload_data(data_dir=args.data_dir)
    elif args.command == "import-guide":
        import_guide(args.items, args.images)
    elif args.command == "import-scan":
        import_scan(args.jsonl, args.target, args.nuclei_version)


if __name__ == "__main__":
    main()

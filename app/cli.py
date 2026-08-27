"""REDAR CLI.

    python -m app.cli init-db
"""
from __future__ import annotations

import argparse
import csv
import sqlite3
from pathlib import Path

from app import __version__
from app.config import settings
from app.domain.enums import ScanStatus
from app.domain.ids import new_id
from app.repository.db import session

# (CSV 파일명, 테이블, ON CONFLICT 대상, 키 컬럼)
#
# component_advisories 충돌 대상이 식(COALESCE)인 이유: uq_advisory 가 식 인덱스이므로
# 컬럼 목록으로는 매칭 불가 (db/schema.sql §4)
#
# guide_mappings 는 CSV 2개가 동일 테이블 적재 (docs/05 §1.2)
_CSV_LOADS: list[tuple[str, str, str, tuple[str, ...]]] = [
    (
        "vuln_type_rules.csv",
        "vuln_type_rules",
        "match_type, match_value",
        ("match_type", "match_value"),
    ),
    (
        "guide_mappings.csv",
        "guide_mappings",
        "match_type, match_value, item_code",
        ("match_type", "match_value", "item_code"),
    ),
    (
        "guide_mappings.templates.csv",
        "guide_mappings",
        "match_type, match_value, item_code",
        ("match_type", "match_value", "item_code"),
    ),
    (
        "component_advisories.csv",
        "component_advisories",
        "component_type, slug, COALESCE(cve_id,''), COALESCE(template_id,'')",
        ("component_type", "slug", "cve_id", "template_id"),
    ),
]

# guide_items(가이드 본문) 미적재. 저작권 대상, 사용자 임포트 (절대규칙 8)


def _upsert_csv(
    conn: sqlite3.Connection,
    path: Path,
    table: str,
    conflict: str,
    keys: tuple[str, ...],
) -> int:
    with path.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        return 0
    cols = list(rows[0])
    updates = [c for c in cols if c not in keys]
    sql = (
        f"INSERT INTO {table} ({', '.join(cols)}) "
        f"VALUES ({', '.join('?' * len(cols))}) "
        f"ON CONFLICT ({conflict}) DO UPDATE SET "
        + ", ".join(f"{c} = excluded.{c}" for c in updates)
    )
    # 빈 문자열 -> NULL. 미변환 시 nullable 컬럼에 '없음'이 두 종류로 혼재
    conn.executemany(sql, [[row[c] or None for c in cols] for row in rows])
    return len(rows)


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


def init_db(db_path: Path | None = None) -> None:
    """스키마 적용 -> 미적용 마이그레이션 -> 번들 CSV upsert. 재실행 안전"""
    target = db_path or settings.DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    with session(target) as conn:
        conn.executescript(settings.SCHEMA_PATH.read_text(encoding="utf-8"))
        for version in _apply_migrations(conn):
            print(f"  migration {version:03d} applied")
        for filename, table, conflict, keys in _CSV_LOADS:
            n = _upsert_csv(conn, settings.DATA_DIR / filename, table, conflict, keys)
            print(f"  {filename} -> {table}: {n} rows")
        conn.commit()

        for table in ("vuln_type_rules", "guide_mappings", "component_advisories"):
            total = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"  {table}: {total} rows total")
    print(f"init-db done: {target}")


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
    sub.add_parser("init-db", help="스키마 생성 + 번들 CSV 적재")

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
        init_db()
    elif args.command == "import-scan":
        import_scan(args.jsonl, args.target, args.nuclei_version)


if __name__ == "__main__":
    main()

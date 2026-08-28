#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""data/*.csv 검증 · 파생 CSV 생성 (오프라인 도구. 런타임 아님)

    python3 tools/build_data_csv.py
    python3 tools/build_data_csv.py --guide-db kisa.db --templates ~/nuclei-templates

저작 CSV — 손으로 관리한다. 이 도구는 읽고 검증만 하며 덮어쓰지 않는다
    data/settings_defaults.csv          SQLite settings 기본값
    data/vuln_type_rules.csv            nuclei tags/cwe -> VulnType
    data/guide_mappings.csv             탐지 -> KISA 점검항목

파생 CSV — --guide-db 지정 시 재생성한다
    data/guide_mappings.templates.csv   CWE 로 안 풀리는 템플릿 예외
    data/component_advisories.csv       플러그인/테마 취약 버전 -> 패치 목표

매핑 값을 이 파일에 상수로 두지 않는다. 코드와 CSV 양쪽에 값이 존재하면
DB 에 들어간 값이 어느 쪽에서 왔는지 추적할 수 없다 (docs/05 §4.2, §4.3)
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# 런타임 코드를 재사용한다. 적재 규칙·Enum 사본을 만들면 검증이 실제 적재와 갈라진다
from app.cli import load_data                      # noqa: E402
from app.config import settings as app_settings    # noqa: E402
from app.domain.enums import VulnType              # noqa: E402

AUTHORED = ("settings_defaults.csv", "vuln_type_rules.csv", "guide_mappings.csv")
DERIVED = ("guide_mappings.templates.csv", "component_advisories.csv")


# ────────────────────────────────────────────────── 검증

def validate(data_dir: Path, guide_db: Path | None) -> None:
    """실제 스키마에 실제 적재기로 넣어 본다.

    CHECK·UNIQUE·NOT NULL 을 스키마가 이미 가지고 있으므로 제약 사본을 두지 않는다
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(app_settings.SCHEMA_PATH.read_text(encoding="utf-8"))
    load_data(conn, data_dir)

    fails: list[str] = []

    unknown_vt = {
        r["vuln_type"] for r in conn.execute(
            "SELECT DISTINCT vuln_type FROM vuln_type_rules"
        )
    } - {v.value for v in VulnType}
    if unknown_vt:
        fails.append(f"VulnType Enum 밖의 값: {sorted(unknown_vt)}")

    no_basis = conn.execute(
        "SELECT match_type, match_value, item_code FROM guide_mappings"
        " WHERE mapping_basis IS NULL OR trim(mapping_basis) = ''"
    ).fetchall()
    if no_basis:
        # 근거 없는 매핑은 나중에 검토가 불가능하다 (docs/05 §4.3)
        fails.append(f"mapping_basis 누락 {len(no_basis)}행: {tuple(no_basis[0])}")

    if guide_db:
        codes = {r[0] for r in sqlite3.connect(guide_db).execute("SELECT code FROM item")}
        missing = {
            r["item_code"] for r in conn.execute(
                "SELECT DISTINCT item_code FROM guide_mappings"
            )
        } - codes
        if missing:
            fails.append(f"가이드에 없는 item_code: {sorted(missing)}")
    else:
        print("  (--guide-db 미지정 → item_code 존재 검증 생략)")

    for table in ("settings", "vuln_type_rules", "guide_mappings",
                  "component_advisories"):
        n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        print(f"  {table:22} {n}행")
    conn.close()

    if fails:
        sys.exit("검증 실패:\n  - " + "\n  - ".join(fails))
    print("  검증 통과")


def authored_cwe_codes(data_dir: Path) -> set[str]:
    """cwe_id 계층이 이미 처리하는 CWE. 템플릿 예외 생성에서 제외 대상"""
    with (data_dir / "guide_mappings.csv").open(encoding="utf-8-sig", newline="") as fh:
        return {r["match_value"] for r in csv.DictReader(fh) if r["match_type"] == "cwe_id"}


# ────────────────────────────────────────────────── 파생 생성

# nuclei-templates 는 WordPress 취약점을 전부 /http/cves/YYYY/ 아래에 둔다.
# 즉 템플릿 파일 경로에는 테마·플러그인 구분 정보가 없다.
# 구분은 템플릿이 요청하는 URL 에 있다:  /wp-content/themes/<slug>
# 파일 경로로 판별하면 테마 59종(twentytwenty*, astra, divi, oceanwp …)이
# 전부 wp_plugin 으로 떨어져 v_patch_plan 조인에서 빠진다. (CHANGELOG §12.3)
_TH_RE = re.compile(r"/wp-content/themes/([a-z0-9][a-z0-9._-]*)", re.I)
_PL_RE = re.compile(r"/wp-content/plugins/([a-z0-9][a-z0-9._-]*)", re.I)


def load_theme_slugs(root: str | None) -> set[str]:
    """themes/ 에만 등장하는 슬러그 집합. 양쪽에 나오면 모호하므로 제외한다."""
    if not root:
        print("  [경고] --templates 미지정 → 테마 판별 불가. 전부 wp_plugin 이 된다.")
        return set()
    th: set[str] = set()
    pl: set[str] = set()
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fn in files:
            if not fn.endswith((".yaml", ".yml")):
                continue
            try:
                txt = Path(dirpath, fn).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            th.update(m.lower() for m in _TH_RE.findall(txt))
            pl.update(m.lower() for m in _PL_RE.findall(txt))
    out = th - pl
    print(f"  테마 슬러그 {len(out)}종 (양쪽 등장 {len(th & pl)}종은 wp_plugin 유지)")
    return out


def vkey(v: str | None) -> str:
    """버전 정렬키. 문자열 비교는 '4.10.1' < '4.9.0' 으로 오판 (docs/02 §3.4)"""
    if not v:
        return ""
    return ".".join(
        f"{int(p):05d}" if p.isdigit() else p.rjust(5, "0")
        for p in str(v).split(".")[:4]
    )


def write_csv(path: Path, header: list[str], rows: list[list]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)
    print(f"  {str(path):44} {len(rows)}행")


def generate_advisories(con: sqlite3.Connection, out: Path, templates: str | None) -> None:
    theme_slugs = load_theme_slugs(templates)
    rows: list[list] = []
    seen: set[tuple] = set()
    for t in con.execute("SELECT * FROM wp_template WHERE is_detect=0"):
        slugs = [x for x in (t["slugs"] or "").split(",") if x]
        cves = [x for x in (t["cve"] or "").split(",") if x] or [""]
        for slug in slugs:
            # 파일 경로가 아니라 슬러그의 출처로 판별한다. load_theme_slugs 주석 참조
            ctype = "wp_theme" if slug.lower() in theme_slugs else "wp_plugin"
            for cve in cves:
                key = (ctype, slug, cve, t["id"])
                if key in seen:
                    continue
                seen.add(key)
                fixed = t["fix_version"] or ""
                rows.append([
                    ctype, slug, cve, t["id"], (t["name"] or "")[:120],
                    f"< {fixed}" if fixed else "", fixed, vkey(fixed),
                    t["severity"] or "", t["cvss"] or "",
                    (t["reference"] or "").split("\n")[0][:160],
                ])
    write_csv(
        out / "component_advisories.csv",
        ["component_type", "slug", "cve_id", "template_id", "title", "affected_range",
         "fixed_version", "fixed_version_key", "severity", "cvss_score", "reference"],
        rows,
    )


def generate_template_exceptions(
    con: sqlite3.Connection, out: Path, cwe_codes: set[str], rules_path: Path
) -> None:
    """CWE 로 안 풀리는 템플릿만 개별 매핑. 키워드 규칙은 외부 파일에서 읽는다"""
    if not rules_path.is_file():
        print(f"  [경고] {rules_path} 없음 → 템플릿 예외 생성 생략")
        return
    import yaml  # 이 경로에서만 필요. 런타임 의존 아님

    keyword_rules = yaml.safe_load(rules_path.read_text(encoding="utf-8")).get("keyword", [])
    rows: list[list] = []
    seen: set[tuple] = set()
    for t in con.execute("SELECT * FROM wp_template WHERE is_detect=0"):
        cwes = [x for x in (t["cwe"] or "").split(",") if x]
        if any(c in cwe_codes for c in cwes):
            continue                       # cwe_id 계층이 처리하므로 제외
        blob = f"{t['id']} {t['name']} {t['tags']} {t['path']}".lower()
        hit = next((r for r in keyword_rules if any(k in blob for k in r["match"])), None)
        if not hit:
            continue
        key = (t["id"], hit["code"])
        if key in seen:
            continue
        seen.add(key)
        conf = "high" if hit["conf"] >= 0.9 else ("medium" if hit["conf"] >= 0.6 else "low")
        rows.append([
            "template_id", t["id"], hit["code"], conf,
            f"CWE 미기재 템플릿. 키워드 근거: {'/'.join(hit['match'][:2])}",
        ])
    write_csv(
        out / "guide_mappings.templates.csv",
        ["match_type", "match_value", "item_code", "confidence", "mapping_basis"],
        rows,
    )


# ────────────────────────────────────────────────── 진입점

def main() -> None:
    ap = argparse.ArgumentParser(description="data/*.csv 검증 · 파생 CSV 생성")
    ap.add_argument("--guide-db", type=Path,
                    help="가이드 추출 DB. 지정 시 파생 CSV 재생성 + item_code 검증")
    ap.add_argument("--templates", help="nuclei-templates 경로. 테마/플러그인 판별에 필요")
    ap.add_argument("--out", type=Path, default=ROOT / "data")
    ap.add_argument("--skip-generate", action="store_true",
                    help="--guide-db 를 줘도 파생 CSV 를 다시 만들지 않음")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    if args.guide_db and not args.skip_generate:
        con = sqlite3.connect(args.guide_db)
        con.row_factory = sqlite3.Row
        has_templates = con.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='wp_template'"
        ).fetchone()[0]
        if has_templates:
            print("파생 CSV 생성")
            generate_advisories(con, args.out, args.templates)
            generate_template_exceptions(
                con, args.out, authored_cwe_codes(args.out),
                args.guide_db.resolve().parent / "mapping_rules.yaml",
            )
        else:
            print("  (wp_template 없음 → 파생 CSV 생성 생략)")
        con.close()

    print("검증")
    validate(args.out, args.guide_db)


if __name__ == "__main__":
    main()

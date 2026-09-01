"""M7 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M7, docs/04 §4).

TC-R05 와 TC-R07 이 "대상과 무관하게 동일한 형식" 요구사항의 유일한 검증 수단임
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.domain import models

from app.domain.enums import Severity, VulnType
from app.report import builder, fallback, renderer
from app.repository.db import session
from app.services import guide_importer, report_service
from app.services.scan_service import ScanError

MOCK_CSV = Path(__file__).parent / "fixtures" / "guide_items_mock.csv"

# 보고서 골격. 이 목록이 바뀌면 대상마다 목차가 달라진다는 뜻임
EXPECTED_SECTIONS = [
    "Part A — 진단 결과",
    "A-1. 개요 및 집계",
    "A-2. 진단 대상 환경",
    "A-3. 심각도별 상세",
    "A-4. 유형별 상세",
    "A-5. 취약점 상세",
    "A-6. 조치 사항",
    "A-7. 오탐 처리 내역",
    "Part B — 주요정보통신기반시설 상세가이드 매핑",
    "B-1. 점검항목 판정 요약",
    "B-2. 점검항목별 상세",
    "B-3. 미매핑 탐지 결과",
    "부록",
    "C-1. 심각도 환산표",
    "C-2. 사용 템플릿 목록",
    "C-3. 진단 범위 및 한계",
]

_HEADINGS = re.compile(r"<h[12][^>]*>(.*?)</h[12]>", re.S)


def _notice_tail() -> str:
    """고지 문구의 고정부. 표현이 바뀌어도 존재 여부는 계속 검증"""
    return models.COVERAGE_NOTICE_TEMPLATE.split("{scope}")[-1].strip()

def _sections(html: str) -> list[str]:
    return [
        re.sub(r"<[^>]+>", "", raw).strip()
        for raw in _HEADINGS.findall(html)
    ]


def _make_scan(conn, scan_id: str, host: str, findings: list[dict]) -> str:
    conn.execute(
        "INSERT OR REPLACE INTO scans (scan_id, status, selection_mode,"
        " collect_environment, tool_version, nuclei_version, started_at, finished_at)"
        " VALUES (?, 'completed', 'filter', 0, '0.3.0', '3.11.1',"
        " '2026-08-28 10:00:00', '2026-08-28 10:01:20')",
        (scan_id,),
    )
    conn.execute(
        "INSERT OR REPLACE INTO scan_targets (scan_id, raw, scheme, host, port)"
        " VALUES (?, ?, 'http', ?, 80)",
        (scan_id, f"http://{host}", host),
    )
    for index, f in enumerate(findings):
        conn.execute(
            "INSERT OR REPLACE INTO findings (finding_id, scan_id, fingerprint,"
            " template_id, target_raw, target_host, name, vuln_type, severity,"
            " severity_guide, cve_ids, cwe_ids, cvss_score, status, status_note,"
            " ev_request, ev_response, ev_curl, component_slug)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f["finding_id"], scan_id, f"fp-{scan_id}-{index}",
                f.get("template_id", "tpl-x"), f"http://{host}/x", host,
                f["name"], f.get("vuln_type", "xss"), f["severity"],
                f.get("severity_guide", "상"),
                json.dumps(f.get("cve_ids", [])) if f.get("cve_ids") else None,
                json.dumps(f.get("cwe_ids", [])) if f.get("cwe_ids") else None,
                f.get("cvss_score"), f.get("status", "open"), f.get("status_note"),
                f.get("ev_request", "GET /x HTTP/1.1"),
                f.get("ev_response", "HTTP/1.1 200 OK"),
                f.get("ev_curl", "curl -i http://host/x"),
                f.get("component_slug"),
            ),
        )
    conn.commit()
    from app.services import guide_service

    guide_service.map_scan(conn, scan_id)
    return scan_id


@pytest.fixture
def guide_loaded(conn):
    guide_importer.import_text(conn, MOCK_CSV.read_text(encoding="utf-8"))
    yield
    conn.execute("DELETE FROM guide_items")
    conn.execute("DELETE FROM guide_items_fts")
    conn.commit()


@pytest.fixture
def scan_with_findings(conn):
    scan_id = _make_scan(conn, "scn_rpt", "wp.local", [
        {"finding_id": "fnd_r1", "name": "XSS 취약점", "severity": "critical",
         "vuln_type": "xss", "cwe_ids": ["CWE-79"], "cvss_score": 9.1},
        {"finding_id": "fnd_r2", "name": "정보 노출", "severity": "medium",
         "vuln_type": "info_disclosure", "cve_ids": ["CVE-2026-63030"],
         "cwe_ids": ["CWE-200"], "component_slug": "contact-form-7"},
        {"finding_id": "fnd_r3", "name": "오탐 항목", "severity": "high",
         "vuln_type": "misconfig", "status": "false_positive",
         "status_note": "인증 미들웨어로 보호됨"},
    ])
    yield scan_id
    conn.execute("DELETE FROM findings WHERE scan_id = 'scn_rpt'")
    conn.execute("DELETE FROM scans WHERE scan_id = 'scn_rpt'")
    conn.commit()


@pytest.fixture
def empty_scan(conn):
    scan_id = _make_scan(conn, "scn_empty", "empty.local", [])
    yield scan_id
    conn.execute("DELETE FROM scans WHERE scan_id = 'scn_empty'")
    conn.commit()


def _report(conn, scan_id, **options):
    view = report_service.create(conn, scan_id, options)
    assert view["status"] == "completed"
    return view["report"]


# ─────────────────────────────── TC-R01 ~ R04 (가이드 · LLM 조합)

def test_tc_r02_guide_yes_llm_no(conn, guide_loaded, scan_with_findings):
    """가이드 O / LLM X -> 산문이 템플릿 문장"""
    report = _report(conn, scan_with_findings, use_llm=False)
    assert report["executive_summary"]["narrative_generated_by"] == "template"
    assert "총 2건" in report["executive_summary"]["narrative"]
    assert report["guide_mapping"]["available"] is True
    assert report["meta"]["llm"]["used"] is False


def test_tc_r04_no_guide_no_llm(conn, scan_with_findings):
    """가이드 X / LLM X -> Part A 정상, Part B 안내"""
    report = _report(conn, scan_with_findings, use_llm=False)
    assert report["executive_summary"]["total_findings"] == 2
    assert report["guide_mapping"]["available"] is False
    assert report["guide_mapping"]["unavailable_note"]
    # 매핑 자체는 남아 있다. 본문만 없음
    assert report["guide_mapping"]["summary"]["vulnerable"] >= 1

    html = renderer.render_html(report)
    assert _sections(html) == EXPECTED_SECTIONS
    assert fallback.GUIDE_UNAVAILABLE in html


def test_target_response_is_not_rendered_as_html(conn, scan_with_findings):
    """대상 서버의 응답 본문이 살아 있는 HTML 로 들어가면 안 됨.

    실제로 Swagger UI 페이지가 보고서 안에서 실행되어 /openapi.json 을 요청하고
    ReDoc 스크립트가 오류를 냈다. 근거 표시가 아니라 코드 실행이 된 것
    """
    report = _report(conn, scan_with_findings)
    payload = (
        '<script>window.__redar_probe=1</script>'
        '<div id="swagger-ui">Failed to load API definition.</div>'
    )
    assert report["findings_detail"], "근거를 넣을 탐지 항목이 있어야 함"
    detail = report["findings_detail"][0]
    detail["evidence"]["included"] = True
    detail["evidence"]["response"] = payload

    html = renderer.render_html(report)
    # 원문은 보이되 태그로 살아나지 않아야 함
    assert "window.__redar_probe" in html
    assert "<script>window.__redar_probe" not in html
    assert '<div id="swagger-ui">' not in html
    assert "&lt;script&gt;" in html


def test_report_lists_only_scanned_targets(conn, scan_with_findings):
    """무응답 대상은 보고서에 나열하지 않되 개수는 밝힘.
    목록을 실으면 조치와 무관한 수백 줄이 되고, 개수를 빼면 범위가 과장됨"""
    conn.execute(
        "UPDATE scan_targets SET reachable = 0 WHERE scan_id = ?",
        (scan_with_findings,),
    )
    conn.execute(
        "INSERT INTO scan_targets (scan_id, raw, host, port, reachable)"
        " VALUES (?, 'localhost:9999', 'localhost', 9999, 1)",
        (scan_with_findings,),
    )
    conn.commit()

    meta = _report(conn, scan_with_findings)["meta"]
    assert meta["targets"] == ["localhost:9999"]
    assert meta["target_probe"]["no_response"] >= 1
    assert meta["target_probe"]["scanned"] == 1


def test_report_css_not_escaped(conn, scan_with_findings):
    """우리 CSS 는 이스케이프 예외. 따옴표가 깨지면 폰트가 적용되지 않음"""
    html = renderer.render_html(_report(conn, scan_with_findings))
    assert '"NanumGothic"' in html
    assert "&quot;NanumGothic&quot;" not in html
    assert "@font-face" in html


def test_tc_r03_no_guide_part_a_intact(conn, scan_with_findings):
    report = _report(conn, scan_with_findings)
    html = renderer.render_html(report)
    assert "XSS 취약점" in html
    assert "A-5. 취약점 상세" in html


# ─────────────────────────────── TC-R05 (0건)

def test_tc_r05_zero_findings_keeps_all_sections(conn, empty_scan):
    """탐지 0건 -> 모든 섹션 '해당 없음', 목차 동일"""
    report = _report(conn, empty_scan)
    assert report["executive_summary"]["total_findings"] == 0

    # 축은 0건이어도 전부 유지됨
    assert len(report["findings_by_severity"]) == len(Severity)
    assert len(report["findings_by_vuln_type"]) == len(VulnType)
    assert all(g["count"] == 0 for g in report["findings_by_severity"])
    assert report["unmapped_findings"] == []
    assert report["false_positives"] == []

    html = renderer.render_html(report)
    assert _sections(html) == EXPECTED_SECTIONS
    assert "해당 없음" in html
    # 0건 문구가 '양호' 로 표현되지 않아야 한다 (절대규칙 10)
    assert _notice_tail() in html


# ─────────────────────────────── TC-R07 (두 대상 목차 일치)

def test_tc_r07_two_different_targets_same_toc(conn, guide_loaded):
    """서로 다른 두 대상 -> 목차 구조 완전 일치"""
    first = _make_scan(conn, "scn_a", "a.local", [
        {"finding_id": "fnd_a1", "name": "RCE", "severity": "critical",
         "vuln_type": "rce", "cwe_ids": ["CWE-94"], "cve_ids": ["CVE-2026-1"]},
    ])
    second = _make_scan(conn, "scn_b", "b.local", [
        {"finding_id": "fnd_b1", "name": "정보 노출", "severity": "low",
         "vuln_type": "info_disclosure"},
        {"finding_id": "fnd_b2", "name": "설정 오류", "severity": "info",
         "vuln_type": "misconfig"},
    ])
    try:
        html_a = renderer.render_html(_report(conn, first))
        html_b = renderer.render_html(_report(conn, second))
        assert _sections(html_a) == _sections(html_b) == EXPECTED_SECTIONS
    finally:
        for scan_id in ("scn_a", "scn_b"):
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()


def test_zero_and_nonzero_scans_share_toc(conn, empty_scan, scan_with_findings):
    """0건 보고서와 탐지 있는 보고서의 목차가 같아야 한다"""
    html_empty = renderer.render_html(_report(conn, empty_scan))
    html_full = renderer.render_html(_report(conn, scan_with_findings))
    assert _sections(html_empty) == _sections(html_full)


# ─────────────────────────────── TC-R08 · R09 (가이드 원문)

def test_tc_r08_part_b_severity_is_guide_original(conn, guide_loaded, scan_with_findings):
    """Part B 중요도는 guide_items 원문 값. 탐지 심각도 환산값이 아님"""
    report = _report(conn, scan_with_findings)
    items = {i["item_code"]: i for i in report["guide_mapping"]["items"]}

    originals = {
        row["item_code"]: row["severity_guide"]
        for row in conn.execute("SELECT item_code, severity_guide FROM guide_items")
    }
    for code, original in originals.items():
        if code in items and items[code]["item_severity"] is not None:
            assert items[code]["item_severity"] == original


def test_tc_r09_remediation_is_verbatim_substring(conn, guide_loaded, scan_with_findings):
    """보고서 조치 문구가 원문에 부분문자열로 존재해야 한다 (재작성 방지)"""
    report = _report(conn, scan_with_findings)
    originals = {
        row["item_code"]: row["remediation"]
        for row in conn.execute("SELECT item_code, remediation FROM guide_items")
    }
    checked = 0
    for item in report["remediation"]:
        original = originals.get(item["item_code"])
        if not original:
            continue
        checked += 1
        assert item["guide_remediation_original"] == original
        assert item["root_fix"]["summary"] in original
        assert item["root_fix"]["is_original"] is True
    assert checked >= 1, "원문이 있는 항목이 최소 1건 있어야 한다"

    html = renderer.render_html(report)
    for original in originals.values():
        if original and original in html:
            break
    else:
        pytest.fail("원문 조치 문구가 HTML 에 인용되지 않았다")


def test_report_carries_no_guide_case_text(conn, guide_loaded, scan_with_findings):
    """사례 본문은 미채택. Report JSON 어디에도 남지 않아야 함"""
    report = _report(conn, scan_with_findings)
    for item in report["guide_mapping"]["items"]:
        assert "case_text" not in item
    for section in report["remediation"]:
        assert "guide_case_text" not in section
    # 조치 근거 자체는 유지됨 - remediation 원문과 출처 페이지는 그대로 인용
    assert all("guide_remediation_original" in s for s in report["remediation"])


# ─────────────────────────────── TC-R10 (커버리지 고지)

def test_tc_r10_coverage_notice_in_part_b(conn, guide_loaded, scan_with_findings):
    report = _report(conn, scan_with_findings)
    notice = report["guide_mapping"]["coverage_notice"]
    assert "자동 점검 대상" in notice
    assert _notice_tail() in notice
    assert notice in renderer.render_html(report)


# ─────────────────────────────── TC-R11 (fixed_version 결측)

def test_tc_r11_missing_fixed_version_has_replacement_text(conn, scan_with_findings):
    """빈칸은 검토자에게 데이터 누락으로 읽힘. 대체 문구를 넣음"""
    conn.execute(
        "INSERT OR REPLACE INTO environment_profiles (profile_id, scan_id,"
        " target_host) VALUES ('env_r', 'scn_rpt', 'wp.local')"
    )
    conn.execute(
        "INSERT OR REPLACE INTO env_components (profile_id, type, slug, version,"
        " confidence) VALUES ('env_r', 'wp_theme', 'astra', '4.1.0', 'high')"
    )
    conn.commit()
    try:
        report = _report(conn, scan_with_findings)
        astra = [p for p in report["patch_plan"] if p["slug"] == "astra"]
        assert astra, "advisory 가 있는 구성요소는 패치 트랙에 나와야 한다"
        entry = astra[0]
        assert not entry["upgrade_to_at_least"]
        assert entry["upgrade_note"] == fallback.NO_UPGRADE_TARGET

        html = renderer.render_html(report)
        assert fallback.NO_UPGRADE_TARGET in html
    finally:
        conn.execute("DELETE FROM environment_profiles WHERE profile_id = 'env_r'")
        conn.commit()


# ─────────────────────────────── TC-R12 (자체 완결형)

def test_tc_r12_html_is_self_contained(conn, guide_loaded, scan_with_findings):
    """외부 URL 참조 0건. CDN·외부 폰트 참조 금지 (절대규칙 4-1)"""
    html = renderer.render_html(_report(conn, scan_with_findings))
    assert renderer.external_references(html) == []
    assert "@font-face" in html
    assert html.count("data:font/woff2;base64,") == 3
    assert "local(" not in html


def test_tc_r12_no_active_content(conn, guide_loaded, scan_with_findings):
    """보고서는 정적 문서. 스크립트가 있으면 대상 응답이 흘러든 것"""
    report = _report(conn, scan_with_findings)
    detail = report["findings_detail"][0]
    detail["evidence"]["included"] = True
    detail["evidence"]["response"] = (
        '<iframe src="/x"></iframe><img src=x onerror="alert(1)">'
    )
    html = renderer.render_html(report)
    assert renderer.active_content(html) == []
    # 이스케이프된 평문으로는 남아야 함. 근거를 지워버리면 안 됨
    assert "onerror" in html


def test_disposition_survives_non_ascii_filename():
    """대상 요약에서 만든 파일명에 '외 3건'·'포트 12개' 처럼 한글이 들어간다.
    HTTP 헤더는 latin-1 이라 그대로 넣으면 500 (RFC 5987 로 실어야 함)"""
    from app.api.reports import _disposition

    header = _disposition("report_대상없음_외3건_20260831.html")
    header.encode("latin-1")                     # 인코딩되지 않으면 여기서 실패
    assert "filename*=UTF-8''" in header
    assert 'filename="' in header                # 구형 클라이언트용 ASCII 이름


def test_download_filename_from_summary(conn, guide_loaded, scan_with_findings):
    """파일명이 실제로 만들어지고 확장자가 맞는지"""
    report = _report(conn, scan_with_findings)
    name = renderer.filename(report, "html")
    assert name.startswith("report_")
    assert name.endswith(".html")


def test_toc_links_to_every_section(conn, guide_loaded, scan_with_findings):
    """목차 항목이 전부 실제 앵커로 이어져야 함. 끊긴 링크는 눌러야 알게 됨"""
    html = renderer.render_html(_report(conn, scan_with_findings))
    hrefs = set(re.findall(r'href="#([a-z0-9-]+)"', html))
    ids = set(re.findall(r'id="([a-z0-9-]+)"', html))
    assert hrefs, "목차 링크가 있어야 함"
    assert hrefs <= ids, f"이어지지 않는 링크: {hrefs - ids}"
    # 절이 13개이므로 절 앵커도 13개
    assert len([i for i in ids if i.startswith("sec-")]) == 13


def test_screen_nav_hidden_in_print(conn, guide_loaded, scan_with_findings):
    """화면용 메뉴는 인쇄에서 숨기되 본문은 그대로 나와야 함"""
    html = renderer.render_html(_report(conn, scan_with_findings))
    print_block = html.split("@media print")[1].split("}\n}")[0]
    # 인쇄에서 숨기는 것은 화면용 메뉴뿐. 본문을 숨기면 PDF 에서 내용이 사라진다
    hidden = [
        line.split("{")[0].strip()
        for line in print_block.splitlines()
        if re.search(r"display:\s*none", line)
    ]
    assert hidden == [".docnav"]


def test_nav_uses_no_script(conn, guide_loaded, scan_with_findings):
    """목차는 앵커만으로 동작. 스크립트를 넣으면 절대규칙 4-1 검사에 걸림"""
    html = renderer.render_html(_report(conn, scan_with_findings))
    assert renderer.active_content(html) == []
    assert renderer.external_references(html) == []


def test_active_content_catches_real_tags():
    """검사 자체가 동작하는지. 통과만 확인하면 규칙이 느슨해져도 모름"""
    assert renderer.active_content("<p>ok</p>") == []
    assert renderer.active_content("&lt;script&gt; onerror= 평문") == []
    assert renderer.active_content("<script>x</script>")
    assert renderer.active_content('<img src=x onerror="alert(1)">')


def test_font_weights_registered_separately():
    """400 과 700 을 각각 등록. 하나만 등록하면 fake bold 가 된다"""
    faces = renderer.font_faces()
    assert "font-weight:400" in faces
    assert "font-weight:700" in faces
    assert faces.count("@font-face") == 3


def test_font_base64_is_cached():
    """보고서마다 재인코딩하면 1.1MB 를 매번 인코딩"""
    renderer.font_faces.cache_clear()
    first = renderer.font_faces()
    assert renderer.font_faces() is first
    assert renderer.font_faces.cache_info().hits >= 1


# ─────────────────────────────── PDF · 파일명 · 옵션

def test_pdf_download_is_rejected_with_guidance(conn, scan_with_findings):
    """PDF 는 WebView 인쇄로 파생. 서버가 만들지 않음 (절대규칙 4-1)"""
    view = report_service.create(conn, scan_with_findings, {})
    with pytest.raises(ScanError) as exc:
        report_service.download(conn, view["report_id"], "pdf")
    assert exc.value.status_code == 501
    assert "인쇄" in exc.value.message


def test_download_formats(conn, scan_with_findings):
    view = report_service.create(conn, scan_with_findings, {})
    html, media, name = report_service.download(conn, view["report_id"], "html")
    assert media.startswith("text/html")
    assert name.endswith(".html")

    raw, media, name = report_service.download(conn, view["report_id"], "json")
    assert media == "application/json"
    assert json.loads(raw)["report_id"] == view["report_id"]


def test_filename_follows_convention(conn, scan_with_findings):
    report = _report(conn, scan_with_findings)
    name = renderer.filename(report, "html")
    assert name.startswith("report_")
    assert name.endswith(".html")
    assert "/" not in name and "\\" not in name


def test_evidence_option_off_removes_evidence(conn, scan_with_findings):
    report = _report(conn, scan_with_findings, include_evidence=False)
    for block in report["findings_detail"]:
        assert block["evidence"]["included"] is False
        assert block["evidence"]["request"] is None
    html = renderer.render_html(report)
    assert "근거 포함 옵션이 꺼져 있어" in html


def test_evidence_truncated_at_limit(conn, scan_with_findings):
    conn.execute(
        "UPDATE findings SET ev_response = ? WHERE finding_id = 'fnd_r1'",
        ("A" * (builder.EVIDENCE_LIMIT + 500),),
    )
    conn.commit()
    report = _report(conn, scan_with_findings)
    block = next(b for b in report["findings_detail"] if b["finding_id"] == "fnd_r1")
    assert builder.TRUNCATION_MARKER in block["evidence"]["response"]


def test_false_positive_excluded_from_counts_but_listed(conn, scan_with_findings):
    report = _report(conn, scan_with_findings)
    assert report["executive_summary"]["total_findings"] == 2      # 오탐 1건 제외
    assert len(report["false_positives"]) == 1
    assert report["false_positives"][0]["note"] == "인증 미들웨어로 보호됨"

    html = renderer.render_html(report)
    assert "집계에서 제외" in html


def test_report_json_is_self_sufficient(conn, guide_loaded, scan_with_findings):
    """렌더러가 JSON 밖 DB 를 조회하면 GUI 미리보기와 파일이 갈라짐"""
    report = _report(conn, scan_with_findings)
    saved = json.loads(builder.dumps(report))
    html = renderer.render_html(saved)         # DB 접근 없이 렌더
    assert _sections(html) == EXPECTED_SECTIONS


def test_report_persisted_with_files(conn, scan_with_findings):
    view = report_service.create(conn, scan_with_findings, {})
    formats = {f["format"] for f in view["files"]}
    assert formats == {"html", "json"}
    for entry in view["files"]:
        path = Path(entry["file_path"])
        assert path.is_file()
        assert entry["size_bytes"] > 0
        assert len(entry["sha256"]) == 64
    report_service.delete(conn, view["report_id"])
    for entry in view["files"]:
        assert not Path(entry["file_path"]).exists()


def test_coverage_values_recorded_on_report_row(conn, guide_loaded, scan_with_findings):
    view = report_service.create(conn, scan_with_findings, {})
    row = conn.execute(
        "SELECT guide_items_total, guide_items_covered, guide_db_available"
        " FROM reports WHERE report_id = ?", (view["report_id"],)
    ).fetchone()
    assert row["guide_items_total"] == 10          # 목 데이터 10행
    assert row["guide_items_covered"] == 36
    assert row["guide_db_available"] == 1


def test_priority_score_comes_from_sql(conn, guide_loaded, scan_with_findings):
    """조치 우선순위는 SQL 이 확정. LLM 미개입"""
    report = _report(conn, scan_with_findings)
    scores = [item["priority_score"] for item in report["remediation"]]
    assert scores == sorted(scores, reverse=True)

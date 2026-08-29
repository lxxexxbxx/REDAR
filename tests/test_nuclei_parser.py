"""M2 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M2).

픽스처는 실제 nuclei v3.11.1 출력 필드 기준. 실제 바이너리 미실행
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

from app.adapters.nuclei import progress, runner
from app.adapters.nuclei.parser import (
    is_truncated,
    parse_line,
    parse_stream,
    truncate_evidence,
)
from app.domain.enums import Severity, SeverityGuide, VulnType
from app.domain.ids import new_id
from app.domain.models import EVIDENCE_MAX_BYTES
from app.repository.db import session
from app.repository.findings import FindingBatchWriter, count_by_scan, insert_findings
from app.repository.rules import load_vuln_type_rules

FIXTURE = Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl"


@pytest.fixture(scope="module")
def rules(db_path):
    with session(db_path) as conn:
        return load_vuln_type_rules(conn)


@pytest.fixture
def scan_id(conn):
    """findings 는 scans 에 FK. 테스트마다 별도 스캔으로 fingerprint 충돌 회피."""
    sid = new_id("scn")
    conn.execute(
        "INSERT INTO scans (scan_id, status, selection_mode)"
        " VALUES (?, 'completed', 'filter')",
        (sid,),
    )
    conn.commit()
    return sid


def _findings(rules, scan_id):
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    return list(parse_stream(lines, scan_id=scan_id, rules=rules))


# ------------------------------------------------------------------ 파싱


def test_fixture_parses_all_lines(rules):
    """6줄(빈 줄 1개 포함) -> 5건."""
    findings = _findings(rules, "scn_x")
    assert len(findings) == 5
    assert [f.template_id for f in findings] == [
        "CVE-2026-33017", "langflow-detect", "http-missing-security-headers",
        "CVE-2026-33017", "swagger-api",
    ]


def test_cve_line_normalized(rules):
    f = _findings(rules, "scn_x")[0]
    assert f.name == "Langflow < 1.9.0 - Remote Code Execution"
    assert f.matcher_name == "dsl-1"
    assert f.severity is Severity.CRITICAL
    assert f.severity_guide is SeverityGuide.SANG
    assert f.vuln_type is VulnType.RCE          # CWE-94
    assert f.cve_ids == ["CVE-2026-33017"]
    assert f.cwe_ids == ["CWE-94"]
    assert f.cvss_score == 9.8
    assert f.cvss_vector.startswith("CVSS:3.1/")
    assert f.detected_at.isoformat().startswith("2026-08-19T06:16:24.123456")
    assert f.evidence.curl_command.startswith("curl ")


def test_target_split_into_host_and_port(rules):
    f = _findings(rules, "scn_x")[0]
    assert (f.target.scheme, f.target.host, f.target.port) == ("http", "localhost", 7860)
    assert f.target.path == "/api/v1/version"


def test_query_string_excluded_from_path_in_fingerprint(rules):
    """matched-at 이 '/docs?ui=1' 이어도 fingerprint 는 '/docs' 기준."""
    swagger = _findings(rules, "scn_x")[4]
    assert swagger.target.path == "/docs"


def test_extracted_results_and_tags(rules):
    detect = _findings(rules, "scn_x")[1]
    assert detect.evidence.extracted_values == ["1.8.1"]
    assert detect.severity is Severity.INFO
    assert detect.vuln_type is VulnType.OTHER   # 자산 식별 템플릿


def test_duplicate_lines_share_fingerprint(rules):
    findings = _findings(rules, "scn_x")
    assert findings[0].fingerprint == findings[3].fingerprint
    assert findings[0].finding_id != findings[3].finding_id


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "not json at all",
        '{"info": {"severity": "high"}}',                    # template-id 없음
        '{"template-id": "t", "info": {}}',                  # 대상 없음
        '{"template-id": "t", "matched-at": "/only/path"}',   # host 없음
        '["array", "not", "object"]',
    ],
)
def test_malformed_lines_skipped(rules, line):
    """한 줄이 깨져도 예외 없이 건너뜀."""
    assert parse_line(line, scan_id="scn_x", rules=rules) is None


def test_unknown_severity_falls_back_to_cvss(rules):
    line = json.dumps({
        "template-id": "t", "matched-at": "http://h/x",
        "info": {"severity": "unknown",
                 "classification": {"cvss-score": 9.8}},
    })
    f = parse_line(line, scan_id="scn_x", rules=rules)
    assert f.severity is Severity.CRITICAL


# ------------------------------------------------------------------ 절단


def test_response_truncated_with_marker():
    big = "A" * (EVIDENCE_MAX_BYTES + 5000)
    result = truncate_evidence(big)
    assert is_truncated(result)
    assert len(result.encode("utf-8")) < len(big.encode("utf-8"))


def test_small_response_untouched():
    assert truncate_evidence("short") == "short"
    assert is_truncated("short") is False
    assert truncate_evidence(None) is None


def test_truncation_does_not_break_multibyte():
    """바이트 절단 지점이 한글 중간이어도 디코딩 실패 없음."""
    result = truncate_evidence("가" * EVIDENCE_MAX_BYTES)
    assert is_truncated(result)
    result.encode("utf-8").decode("utf-8")


def test_parse_line_truncates_oversized_response(rules):
    line = json.dumps({
        "template-id": "t", "matched-at": "http://h/x",
        "info": {"severity": "info"},
        "response": "B" * (EVIDENCE_MAX_BYTES + 100),
    })
    f = parse_line(line, scan_id="scn_x", rules=rules)
    assert is_truncated(f.evidence.response)


# ------------------------------------------------------------------ 저장


def test_duplicate_fingerprint_stored_once(conn, rules, scan_id):
    findings = _findings(rules, scan_id)
    inserted = insert_findings(conn, findings)
    assert len(findings) == 5
    assert inserted == 4                       # 중복 1건 제외
    assert count_by_scan(conn, scan_id) == 4


def test_batch_writer_counts_duplicates(conn, rules, scan_id):
    with FindingBatchWriter(conn, batch_size=2) as writer:
        for finding in _findings(rules, scan_id):
            writer.add(finding)
    assert (writer.inserted, writer.skipped) == (4, 1)


def test_interrupted_scan_preserves_saved_findings(db_path, rules, scan_id):
    """중단 시 이미 처리된 finding 보존. 배치 커밋이 안 되면 전량 소실."""
    findings = _findings(rules, scan_id)
    with session(db_path) as write_conn:
        with pytest.raises(RuntimeError):
            # batch_size 를 크게 두어 자동 커밋 전에 중단
            with FindingBatchWriter(write_conn, batch_size=100, interval_sec=99) as w:
                w.add(findings[0])
                w.add(findings[1])
                raise RuntimeError("프로세스 강제 종료")

    with session(db_path) as read_conn:
        assert count_by_scan(read_conn, scan_id) == 2


# ------------------------------------------------------------------ 진행률


def test_stats_line_parsed():
    line = ("[0:00:05] | Templates: 1234 | Hosts: 1 | RPS: 123 | Matched: 5 "
            "| Errors: 2 | Requests: 615/1234 (49%)")
    p = progress.parse_stats_line(line)
    assert (p.requests_done, p.requests_total) == (615, 1234)
    assert p.percent == pytest.approx(49.8, abs=0.1)
    assert (p.templates, p.hosts, p.matched, p.errors) == (1234, 1, 5, 2)


@pytest.mark.parametrize(
    "line", ["", "[INF] Templates loaded for current scan: 123", "a | b | c"]
)
def test_non_stats_lines_return_none(line):
    assert progress.parse_stats_line(line) is None


# ------------------------------------------------------------------ 실행


def test_build_command_contains_required_flags():
    cmd = runner.build_command(
        runner.RunOptions(targets=["http://localhost:7860"], tags=["cve"],
                          severities=["critical", "high"], rate_limit=50),
        exe="nuclei",
    )
    assert cmd[0] == "nuclei"
    for flag in ("-jsonl", "-silent", "-nc", "-stats", "-duc"):
        assert flag in cmd
    assert cmd[cmd.index("-target") + 1] == "http://localhost:7860"
    assert cmd[cmd.index("-tags") + 1] == "cve"
    assert cmd[cmd.index("-severity") + 1] == "critical,high"
    assert cmd[cmd.index("-rl") + 1] == "50"


def test_build_command_requires_binary_and_targets(monkeypatch):
    # exe="" 는 falsy 라 settings.nuclei_bin() 로 넘어간다. 부재 조건을 직접 생성
    monkeypatch.setattr(runner.settings, "nuclei_bin", lambda: None)
    with pytest.raises(RuntimeError):
        runner.build_command(runner.RunOptions(targets=["h"]), exe="")
    with pytest.raises(ValueError):
        runner.build_command(runner.RunOptions(targets=[]), exe="nuclei")


_FAKE_NUCLEI = (
    "import sys, time\n"
    "for i in range(3):\n"
    "    sys.stdout.write('{\"template-id\": \"t%d\"}\\n' % i)\n"
    "    sys.stdout.flush()\n"
    "sys.stderr.write('| Requests: 1/2 (50%)\\n')\n"
    "sys.stderr.flush()\n"
    "time.sleep(60)\n"
)


def test_run_streams_lines_then_cancels():
    """stdout 라인 스트림 + 취소로 프로세스 종료."""
    cancel = threading.Event()
    out: list[str] = []
    err: list[str] = []

    def on_stdout(line: str) -> None:
        out.append(line)
        if len(out) == 3:
            cancel.set()

    code = runner.run(
        [sys.executable, "-c", _FAKE_NUCLEI],
        on_stdout_line=on_stdout,
        on_stderr_line=err.append,
        cancel=cancel,
    )
    assert len(out) == 3
    assert json.loads(out[0])["template-id"] == "t0"
    assert code is not None                    # 종료됨


# 픽스처를 stdout 으로 흘리고 stats 를 stderr 로 내는 가짜 nuclei
_FAKE_SCAN = (
    "import sys\n"
    "sys.stdout.write(open(sys.argv[1], encoding='utf-8').read())\n"
    "sys.stderr.write('[0:00:01] | Templates: 5 | Requests: 5/5 (100%)\\n')\n"
)


def test_end_to_end_stream_to_db(db_path, rules, scan_id):
    """실행 -> JSONL 스트림 파싱 -> 배치 저장 -> 진행률 수신. nuclei 미실행."""
    received: list[progress.Progress] = []

    with session(db_path) as conn:
        with FindingBatchWriter(conn, batch_size=2) as writer:

            def on_stdout(line: str) -> None:
                finding = parse_line(line, scan_id=scan_id, rules=rules)
                if finding is not None:
                    writer.add(finding)

            def on_stderr(line: str) -> None:
                stats = progress.parse_stats_line(line)
                if stats is not None:
                    received.append(stats)

            code = runner.run(
                [sys.executable, "-c", _FAKE_SCAN, str(FIXTURE)],
                on_stdout_line=on_stdout,
                on_stderr_line=on_stderr,
            )

    assert code == 0
    assert (writer.inserted, writer.skipped) == (4, 1)
    with session(db_path) as read_conn:
        assert count_by_scan(read_conn, scan_id) == 4
    assert received and received[-1].percent == 100.0

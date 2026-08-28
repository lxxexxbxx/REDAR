"""M5 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M5).

nuclei 는 실행하지 않는다. 문법 검증은 미설치 시 건너뜀으로 보고되어야 하고,
드라이런은 JSONL 을 돌려주는 러너를 주입한다
"""
from __future__ import annotations

import json

import pytest
import yaml

from app.repository import templates as template_repo
from app.repository.db import session
from app.services import template_builder as builder
from app.services import template_service as service
from app.services import template_validator as validator
from app.services.scan_service import ScanError

VALID_FORM = {
    "info": {"id": "demo-rce", "name": "Demo RCE", "severity": "critical",
             "tags": ["wordpress", "rce"]},
    "classification": {"cve_id": "CVE-2026-63030", "cwe_id": "CWE-94",
                       "cvss_score": 9.8},
    "http": [{"method": "POST", "path": "{{BaseURL}}/wp-json/xyz/v1/run",
              "body": "cmd=id"}],
    "matchers": [
        {"type": "status", "values": ["200"]},
        {"type": "word", "part": "body", "values": ["uid="]},
    ],
    "matchers-condition": "and",
}

# 공식 템플릿에 흔한 미지원 문법: workflows·extractors·variables
OFFICIAL_YAML = """
id: CVE-2026-33017
info:
  name: Langflow RCE
  severity: critical
  author: himind
  tags: cve,cve2026,langflow,rce
  classification:
    cve-id: CVE-2026-33017
    cwe-id: CWE-94
    cvss-score: 9.8
  metadata:
    shodan-query: http.favicon.hash:1727196746
variables:
  marker: "{{randstr}}"
http:
  - method: POST
    path:
      - "{{BaseURL}}/api/v1/build_public_tmp"
    headers:
      Content-Type: application/json
    body: '{"x":1}'
    extractors:
      - type: regex
        regex:
          - "uid=[0-9]+"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "uid="
      - type: binary
        binary:
          - "504b0304"
workflows:
  - template: other.yaml
"""


@pytest.fixture
def custom_dir(tmp_path, monkeypatch):
    """템플릿 쓰기를 임시 디렉터리로 격리. 저장소 templates/ 를 건드리지 않는다"""
    target = tmp_path / "custom"
    target.mkdir()
    monkeypatch.setattr("app.config.settings.CUSTOM_DIR", target, raising=False)
    monkeypatch.setattr("app.config.settings.OFFICIAL_DIR", tmp_path / "official",
                        raising=False)
    return target


@pytest.fixture
def clean_templates(conn):
    yield
    conn.execute("DELETE FROM templates")
    conn.commit()


# ─────────────────────────────────────────── 폼 -> YAML (완료 조건 1)

def test_form_builds_valid_yaml_and_passes_policy():
    text = builder.build(VALID_FORM)
    document = yaml.safe_load(text)

    assert document["id"] == "demo-rce"
    assert document["info"]["severity"] == "critical"
    assert document["info"]["classification"]["cve-id"] == "CVE-2026-63030"
    assert document["http"][0]["method"] == "POST"
    assert document["http"][0]["path"] == ["{{BaseURL}}/wp-json/xyz/v1/run"]

    result = validator.validate(text)
    assert result["policy"]["valid"] is True
    assert result["policy"]["errors"] == []
    # nuclei 미설치는 검증 실패가 아니다. 건너뜀으로 보고한다
    assert result["syntax"]["skipped"] is True
    assert result["valid"] is True


def test_round_trip_is_lossless():
    text = builder.build(VALID_FORM)
    parsed = builder.parse(text)
    assert parsed["unsupported_fields"] == []
    assert builder.build(parsed["form"]) == text


def test_matchers_get_names_for_dryrun_attribution():
    """드라이런이 matcher 별 결과를 특정하려면 이름이 필요하다"""
    document = yaml.safe_load(builder.build(VALID_FORM))
    names = [m["name"] for m in document["http"][0]["matchers"]]
    assert names == ["m0", "m1"]


# ─────────────────────────────────────────── YAML 인젝션 · 경로 조작 (보안)

@pytest.mark.parametrize("bad_id", [
    "../../etc/passwd", "../evil", "a/b", "UPPER", "with space", "sym;colon", "",
])
def test_bad_template_id_rejected(bad_id):
    form = {**VALID_FORM, "info": {**VALID_FORM["info"], "id": bad_id}}
    with pytest.raises(builder.BuildError) as exc:
        builder.build(form)
    assert exc.value.field == "info.id"


def test_traversal_id_rejected_at_path_layer():
    """빌더를 우회해 서비스로 들어와도 경로 계층에서 막힌다"""
    with pytest.raises(ScanError) as exc:
        service.custom_path("../../evil")
    assert exc.value.status_code == 400


def test_yaml_injection_is_quoted_not_interpolated():
    """폼 값이 YAML 구조를 만들지 못해야 한다"""
    form = {
        **VALID_FORM,
        "info": {**VALID_FORM["info"], "name": "x\ninfo:\n  severity: info\nid: pwned"},
    }
    document = yaml.safe_load(builder.build(form))
    assert document["id"] == "demo-rce"                  # 주입된 id 가 이기지 못함
    assert document["info"]["severity"] == "critical"
    assert "pwned" in document["info"]["name"]           # 값으로만 남는다


@pytest.mark.parametrize("field,value", [
    ("cve_id", "CVE-63030"),
    ("cve_id", "2026-63030"),
    ("cwe_id", "94"),
])
def test_classification_format_enforced(field, value):
    form = {**VALID_FORM, "classification": {field: value}}
    with pytest.raises(builder.BuildError):
        builder.build(form)


@pytest.mark.parametrize("form,field", [
    ({"info": {"id": "x", "name": "n", "severity": "urgent"}}, "info.severity"),
    ({"info": {"id": "x", "name": "", "severity": "high"}}, "info.name"),
])
def test_required_fields_enforced(form, field):
    with pytest.raises(builder.BuildError) as exc:
        builder.build(form)
    assert exc.value.field == field


def test_missing_matchers_rejected():
    form = {k: v for k, v in VALID_FORM.items() if k != "matchers"}
    with pytest.raises(builder.BuildError) as exc:
        builder.build(form)
    assert exc.value.field == "matchers"


# ─────────────────────────────────────────── 공식 템플릿 파싱 (완료 조건 2)

def test_official_template_parses_with_unsupported_fields():
    """미지원 문법은 예외가 아니라 unsupported_fields 로 반환된다"""
    parsed = builder.parse(OFFICIAL_YAML)
    unsupported = parsed["unsupported_fields"]

    assert "workflows" in unsupported
    assert "variables" in unsupported
    assert "info.metadata" in unsupported
    assert any("extractors" in f for f in unsupported)
    assert any("binary" in f for f in unsupported)

    # 나머지는 폼에 채워져 있어야 한다
    form = parsed["form"]
    assert form["info"]["id"] == "CVE-2026-33017"
    assert form["info"]["severity"] == "critical"
    assert form["classification"]["cve_id"] == "CVE-2026-33017"
    assert form["http"][0]["method"] == "POST"
    assert form["http"][0]["headers"] == {"Content-Type": "application/json"}
    assert [m["type"] for m in form["matchers"]] == ["status", "word"]
    assert form["info"]["tags"] == ["cve", "cve2026", "langflow", "rce"]


def test_broken_yaml_reports_field_not_crash():
    with pytest.raises(builder.BuildError) as exc:
        builder.parse("id: [unclosed")
    assert exc.value.field == "yaml"


# ─────────────────────────────────────────── LOOSE_MATCHER (완료 조건 3)

def test_status_only_matcher_warns():
    form = {**VALID_FORM, "matchers": [{"type": "status", "values": ["200"]}]}
    policy = validator.check_policy(builder.build(form))

    assert policy["valid"] is True                       # 오류가 아니라 경고
    codes = [w["code"] for w in policy["warnings"]]
    assert codes == ["LOOSE_MATCHER"]
    assert policy["warnings"][0]["suggestion"]


def test_status_plus_word_does_not_warn():
    policy = validator.check_policy(builder.build(VALID_FORM))
    assert policy["warnings"] == []


def test_create_returns_warnings(conn, custom_dir, clean_templates):
    form = {**VALID_FORM, "matchers": [{"type": "status", "values": ["200"]}]}
    result = service.create(conn, form)
    assert [w["code"] for w in result["warnings"]] == ["LOOSE_MATCHER"]


# ─────────────────────────────────────────── 저장 · official 보호

def test_create_writes_file_and_indexes(conn, custom_dir, clean_templates):
    result = service.create(conn, VALID_FORM)
    assert result["template_id"] == "demo-rce"
    assert (custom_dir / "demo-rce.yaml").is_file()

    row = template_repo.get(conn, "demo-rce")
    assert row["source"] == "custom"
    assert row["severity"] == "critical"
    assert row["cve_ids"] == ["CVE-2026-63030"]
    assert row["vuln_type"] == "rce"                     # CWE-94 -> rce
    assert row["tags"] == ["wordpress", "rce"]


def test_duplicate_id_conflicts(conn, custom_dir, clean_templates):
    service.create(conn, VALID_FORM)
    with pytest.raises(ScanError) as exc:
        service.create(conn, VALID_FORM)
    assert exc.value.status_code == 409


def test_official_template_cannot_be_modified(conn, custom_dir, clean_templates):
    template_repo.upsert(conn, {
        "template_id": "cve-2026-33017", "source": "official",
        "file_path": "official/x.yaml", "name": "Official", "severity": "high",
    })
    for action in (
        lambda: service.update(conn, "cve-2026-33017", VALID_FORM),
        lambda: service.delete(conn, "cve-2026-33017"),
    ):
        with pytest.raises(ScanError) as exc:
            action()
        assert exc.value.status_code == 403


def test_fork_creates_editable_copy(conn, custom_dir, clean_templates, tmp_path):
    official = tmp_path / "official"
    official.mkdir(exist_ok=True)
    path = official / "src.yaml"
    path.write_text(builder.build(VALID_FORM), encoding="utf-8")
    template_repo.upsert(conn, {
        "template_id": "demo-rce", "source": "official",
        "file_path": str(path), "name": "Demo", "severity": "critical",
    })

    result = service.fork(conn, "demo-rce", "demo-rce-mine")
    assert result["source"] == "custom"
    assert yaml.safe_load(result["yaml"])["id"] == "demo-rce-mine"
    assert (custom_dir / "demo-rce-mine.yaml").is_file()


def test_id_change_on_update_rejected(conn, custom_dir, clean_templates):
    service.create(conn, VALID_FORM)
    renamed = {**VALID_FORM, "info": {**VALID_FORM["info"], "id": "other-id"}}
    with pytest.raises(ScanError) as exc:
        service.update(conn, "demo-rce", renamed)
    assert "fork" in exc.value.message


def test_index_all_picks_up_manually_added_files(conn, custom_dir, clean_templates):
    """사용자가 파일을 직접 넣는 경로. GUI 없이도 동작해야 한다"""
    (custom_dir / "manual.yaml").write_text(
        builder.build({**VALID_FORM, "info": {**VALID_FORM["info"], "id": "manual"}}),
        encoding="utf-8",
    )
    counts = service.index_all(conn)
    assert counts["custom"] == 1
    assert template_repo.get(conn, "manual") is not None


def test_detection_template_flagged(conn, custom_dir, clean_templates):
    form = {**VALID_FORM, "info": {**VALID_FORM["info"], "id": "wp-detect",
                                   "tags": ["tech", "wordpress"]}}
    service.create(conn, form)
    assert template_repo.get(conn, "wp-detect")["is_detection"] is True


# ─────────────────────────────────────────── 드라이런 (완료 조건 4)

def _dryrun_runner(matched_ids: set[str]):
    """nuclei 대체. 매칭된 템플릿만 JSONL 로 출력하는 동작을 모사"""

    def run(root, target, timeout_sec) -> list[str]:
        lines = []
        for path in sorted(root.glob("*.yaml")):
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            if document["id"] in matched_ids:
                lines.append(json.dumps({
                    "template-id": document["id"],
                    "matched-at": target,
                    "request": "POST /wp-json/xyz/v1/run HTTP/1.1",
                    "response": "HTTP/1.1 200 OK\n\nuid=0(root)",
                }))
        return lines

    return run


@pytest.fixture
def allowlisted(conn):
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('target_allowlist', ?)"
        " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (json.dumps(["example.com"]),),
    )
    conn.commit()
    yield
    conn.execute("UPDATE settings SET value = '[]' WHERE key = 'target_allowlist'")
    conn.commit()


def test_dryrun_identifies_failing_matcher(conn, allowlisted):
    """matched: false 일 때 어느 matcher 에서 실패했는지 특정되어야 한다"""
    text = builder.build(VALID_FORM)
    # status 변형만 매칭. word 변형과 원본은 미매칭
    result = service.dryrun(
        conn, text, "http://example.com",
        runner=_dryrun_runner({"demo-rce-redar-m0"}),
    )

    assert result["matched"] is False
    results = result["requests"][0]["matcher_results"]
    assert [(r["type"], r["matched"]) for r in results] == [
        ("status", True), ("word", False),
    ]


def test_dryrun_reports_match_with_evidence(conn, allowlisted):
    text = builder.build(VALID_FORM)
    result = service.dryrun(
        conn, text, "http://example.com",
        runner=_dryrun_runner(
            {"demo-rce", "demo-rce-redar-m0", "demo-rce-redar-m1"}
        ),
    )
    assert result["matched"] is True
    assert result["requests"][0]["response_status"] == 200
    assert "uid=" in result["requests"][0]["response_excerpt"]
    assert all(r["matched"] for r in result["requests"][0]["matcher_results"])
    assert result["duration_ms"] >= 0


def test_dryrun_enforces_allowlist(conn, allowlisted):
    with pytest.raises(ScanError) as exc:
        service.dryrun(
            conn, builder.build(VALID_FORM), "http://evil.example.net",
            runner=_dryrun_runner(set()),
        )
    assert exc.value.code == "INVALID_REQUEST"
    assert "allowlist" in exc.value.message


# ─────────────────────────────────────────── sync (완료 조건 5)

def test_sync_blocked_in_offline_mode(conn):
    conn.execute("UPDATE settings SET value = 'true' WHERE key = 'offline_mode'")
    conn.commit()
    with pytest.raises(ScanError) as exc:
        service.sync(conn, runner=lambda: None)
    assert exc.value.status_code == 403
    assert exc.value.code == "OFFLINE_MODE_BLOCKED"


def test_sync_blocked_when_endpoint_disabled(conn):
    conn.execute("UPDATE settings SET value = 'false' WHERE key = 'offline_mode'")
    conn.commit()
    try:
        with pytest.raises(ScanError) as exc:
            service.sync(conn, runner=lambda: None)
        assert exc.value.status_code == 403
    finally:
        conn.execute("UPDATE settings SET value = 'true' WHERE key = 'offline_mode'")
        conn.commit()


def test_sync_runs_when_explicitly_enabled(conn, custom_dir, clean_templates):
    conn.execute("UPDATE settings SET value = 'false' WHERE key = 'offline_mode'")
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('ext_template_sync_enabled','true')"
        " ON CONFLICT (key) DO UPDATE SET value = excluded.value"
    )
    conn.commit()
    called: list[str] = []
    try:
        result = service.sync(conn, runner=lambda: called.append("run"))
        assert called == ["run"]
        assert set(result) >= {"updated", "added", "removed", "revision"}
    finally:
        conn.execute("UPDATE settings SET value = 'true' WHERE key = 'offline_mode'")
        conn.execute(
            "UPDATE settings SET value = 'false' WHERE key = 'ext_template_sync_enabled'"
        )
        conn.commit()

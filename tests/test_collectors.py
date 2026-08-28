"""M4 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M4).

실제 대상에 요청을 보내지 않는다. HTTP 계층을 주입해 응답을 고정한다
"""
from __future__ import annotations

import pytest

from app.collectors import base as collectors
from app.collectors.base import Response, TargetContext
from app.domain.enums import Confidence
from app.repository import environment as env_repo
from app.repository.db import session
from app.services import environment_service as svc

WP_HTML = """<html><head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/style.css?ver=5.9.3">
<link rel="stylesheet" href="/wp-content/plugins/booked/css/a.css?ver=6.4.2">
<script src="/wp-content/themes/twentytwentyone/js/app.js?ver=1.4"></script>
</head><body>hi</body></html>"""


def _responder(table: dict[str, Response], default: Response | None = None):
    """경로 -> 응답 고정. 표에 없으면 404"""

    def fetch(url: str, *, method: str = "GET", timeout: int = 5) -> Response:
        rest = url.split("://", 1)[1]
        path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
        return table.get(path, default or Response(404, {}, "not found", url))

    return fetch


def _wordpress_site(**overrides) -> dict[str, Response]:
    table = {
        "/": Response(
            200, {"server": "Apache/2.4.52 (Ubuntu)", "x-powered-by": "PHP/7.4.33"},
            WP_HTML, "http://wp.local/",
        ),
        "/readme.html": Response(
            200, {}, "<h1>WordPress</h1> Version 6.4.2", "http://wp.local/readme.html"
        ),
        "/xmlrpc.php": Response(
            405, {}, "XML-RPC server accepts POST requests only.",
            "http://wp.local/xmlrpc.php",
        ),
        "/wp-json/wp/v2/users": Response(
            200, {}, '[{"id":1,"slug":"admin"}]', "http://wp.local/wp-json/wp/v2/users"
        ),
        "/wp-login.php": Response(
            200, {}, '<form><input name="user_login"></form>',
            "http://wp.local/wp-login.php",
        ),
        "/wp-admin/": Response(200, {}, "dashboard", "http://wp.local/wp-admin/"),
    }
    table.update(overrides)
    return table


def _ctx(table: dict[str, Response], **kwargs) -> TargetContext:
    return TargetContext(
        scheme="http", host="wp.local", port=8080,
        http=_responder(table), **kwargs,
    )


# ─────────────────────────────────────────────── 레지스트리 · 순서

def test_registry_discovers_collectors_from_files():
    """파일 추가만으로 등록되어야 한다. 등록표를 따로 두면 누락이 생긴다"""
    keys = [c.key for c in collectors.registry()]
    assert keys == ["generic-http", "wordpress", "apache"]


def test_registry_order_is_generic_then_app_then_middleware():
    orders = [c.order for c in collectors.registry()]
    assert orders == sorted(orders)
    assert orders[0] == collectors.ORDER_GENERIC


def test_describe_matches_api_shape():
    for item in collectors.describe():
        assert set(item) == {"key", "label", "version", "enabled", "detects"}
        assert item["detects"]


# ─────────────────────────────────────────────── 읽기 전용 (M4 규칙 1)

@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH"])
def test_write_methods_are_blocked(method):
    """대상 상태를 바꾸는 요청은 코드 수준에서 막는다"""
    with pytest.raises(ValueError, match="읽기 전용"):
        collectors.fetch_url("http://wp.local/", method=method)


def test_collectors_send_only_get(monkeypatch):
    seen: list[str] = []

    def fetch(url: str, *, method: str = "GET", timeout: int = 5) -> Response:
        seen.append(method)
        return _responder(_wordpress_site())(url, method=method, timeout=timeout)

    ctx = TargetContext(scheme="http", host="wp.local", port=80, http=fetch)
    for collector in collectors.registry():
        if collector.applicable(ctx):
            collector.collect(ctx)
    assert set(seen) == {"GET"}


# ─────────────────────────────────────────────── 노출 항목 정본 (M4 완료 조건)

def _collector_exposure_keys(ctx: TargetContext) -> set[str]:
    keys: set[str] = set()
    for collector in collectors.registry():
        if not collector.applicable(ctx):
            continue
        result = collector.collect(ctx)
        ctx.collected[collector.key] = result
        keys |= {e.key for e in result.exposures}
    return keys


def test_exposure_keys_match_guide_mappings(conn):
    """수집기가 만드는 키와 매핑 테이블의 키가 정확히 일치해야 한다.

    매핑에만 있는 키는 영원히 판정되지 않고, 수집기에만 있는 키는 가이드에 연결되지 않는다
    (docs/00 §1.2 정본 11종)
    """
    produced = _collector_exposure_keys(_ctx(_wordpress_site()))
    mapped = {
        r["match_value"]
        for r in conn.execute(
            "SELECT DISTINCT match_value FROM guide_mappings"
            " WHERE match_type = 'exposure_key'"
        )
    }
    assert produced == mapped
    assert len(produced) == 11


def test_every_exposure_is_reported_even_when_false():
    """0건이어도 항목이 사라지지 않는다 (절대규칙 4)"""
    keys = _collector_exposure_keys(_ctx(_wordpress_site(
        **{
            "/xmlrpc.php": Response(404, {}, "", "http://wp.local/xmlrpc.php"),
            "/readme.html": Response(404, {}, "", "http://wp.local/readme.html"),
            "/wp-json/wp/v2/users": Response(
                401, {}, "", "http://wp.local/wp-json/wp/v2/users"
            ),
        }
    )))
    assert len(keys) == 11


# ─────────────────────────────────────────────── 판정 내용

def test_wordpress_version_and_components():
    ctx = _ctx(_wordpress_site())
    ctx.collected["generic-http"] = collectors.registry()[0].collect(ctx)
    result = collectors.registry()[1].collect(ctx)

    assert result.application.product == "WordPress"
    assert result.application.version == "6.4.2"
    assert result.application.confidence is Confidence.HIGH

    by_slug = {c.slug: c for c in result.components}
    assert by_slug["contact-form-7"].version == "5.9.3"
    assert by_slug["contact-form-7"].type == "wp_plugin"
    assert by_slug["twentytwentyone"].type == "wp_theme"
    # ver 이 본체 버전과 같으면 캐시 버스터일 수 있어 확정하지 않는다 (M4 규칙 3)
    assert by_slug["booked"].version is None
    assert by_slug["booked"].confidence is Confidence.LOW


def test_version_unknown_is_none_and_low():
    """확신 못 하면 None + low. 추정값을 확정처럼 반환하지 않는다 (M4 규칙 3)"""
    ctx = _ctx({
        "/": Response(200, {}, '<link href="/wp-content/plugins/x/a.css">',
                      "http://wp.local/"),
    })
    result = collectors.registry()[1].collect(ctx)
    assert result.application.version is None
    assert result.application.confidence is Confidence.LOW


def test_plaintext_target_is_tls_weak():
    result = collectors.registry()[0].collect(_ctx(_wordpress_site()))
    tls = next(e for e in result.exposures if e.key == "tls_weak_config")
    assert tls.value is True
    assert "평문" in tls.evidence


def test_login_ratelimit_not_claimed_when_limiter_present():
    """제한 플러그인이 탐지되면 '제한 없음' 으로 단정하지 않는다"""
    html = WP_HTML.replace("booked", "wordfence")
    ctx = _ctx(_wordpress_site(
        **{"/": Response(200, {}, html, "http://wp.local/")}
    ))
    result = collectors.registry()[1].collect(ctx)
    exposure = next(e for e in result.exposures if e.key == "wp_login_no_ratelimit")
    assert exposure.value is False
    assert "wordfence" in exposure.evidence


def test_admin_redirect_to_login_is_not_public():
    ctx = _ctx(_wordpress_site(**{
        "/wp-admin/": Response(200, {}, "", "http://wp.local/wp-login.php?redirect_to=x")
    }))
    result = collectors.registry()[1].collect(ctx)
    exposure = next(e for e in result.exposures if e.key == "admin_page_public")
    assert exposure.value is False


def test_backup_file_evidence_has_no_body():
    """wp-config 백업 본문에는 DB 자격증명이 있다. 근거에 본문을 남기지 않는다"""
    secret = "define('DB_PASSWORD', 'hunter2');"
    ctx = _ctx(_wordpress_site(**{
        "/wp-config.php.bak": Response(
            200, {}, secret, "http://wp.local/wp-config.php.bak"
        )
    }))
    result = collectors.registry()[1].collect(ctx)
    exposure = next(e for e in result.exposures if e.key == "dir_backup_files")
    assert exposure.value is True
    assert "hunter2" not in exposure.evidence
    assert "DB_PASSWORD" not in exposure.evidence


def test_wordpress_skipped_on_non_wordpress_target():
    """무관한 대상에 8회 요청하지 않는다"""
    ctx = _ctx({"/": Response(200, {"server": "nginx"}, "<html>plain</html>",
                              "http://x.local/")})
    assert collectors.registry()[1].applicable(ctx) is False


# ─────────────────────────────────────────────── 실패 격리 (M4 규칙 2)

def test_collector_failure_is_recorded_and_scan_continues(conn, monkeypatch):
    class Broken:
        key = "broken"
        label = "고장난 수집기"
        version = "0.0.0"
        detects = ("nothing",)
        order = 15

        def applicable(self, ctx):
            return True

        def collect(self, ctx):
            raise RuntimeError("의도적 실패")

    original = collectors.registry
    monkeypatch.setattr(
        collectors, "registry", lambda: [*original(), Broken()]
    )

    conn.execute(
        "INSERT OR IGNORE INTO scans (scan_id, status, selection_mode)"
        " VALUES ('scn_fail', 'running', 'environment_driven')"
    )
    conn.commit()
    result = svc.collect_target(
        conn, "scn_fail", "http://wp.local:8080",
        http=_responder(_wordpress_site()),
    )

    assert result.collectors_failed == ["broken"]
    assert "wordpress" in result.collectors_run     # 나머지는 계속 실행됨
    assert len(result.exposures) == 11


# ─────────────────────────────────────────────── 저장 · 조회

@pytest.fixture
def collected(conn):
    conn.execute(
        "INSERT OR IGNORE INTO scans (scan_id, status, selection_mode)"
        " VALUES ('scn_env', 'running', 'environment_driven')"
    )
    conn.commit()
    return svc.collect_target(
        conn, "scn_env", "http://wp.local:8080",
        http=_responder(_wordpress_site()),
    )


def test_profile_round_trip(conn, collected):
    profiles = env_repo.profiles(conn, "scn_env")
    assert len(profiles) == 1
    profile = profiles[0]
    assert profile["target_host"] == "wp.local:8080"
    assert profile["application"]["product"] == "WordPress"
    assert profile["application"]["version"] == "6.4.2"
    assert len(profile["exposures"]) == 11
    assert profile["collectors_run"] == ["generic-http", "wordpress", "apache"]
    assert profile["collectors_failed"] == []


def test_recollect_does_not_duplicate_rows(conn, collected):
    svc.collect_target(
        conn, "scn_env", "http://wp.local:8080",
        http=_responder(_wordpress_site()),
    )
    profiles = env_repo.profiles(conn, "scn_env")
    assert len(profiles) == 1
    assert len(profiles[0]["exposures"]) == 11


def test_version_null_is_stored_as_null(conn, collected):
    profile = env_repo.profiles(conn, "scn_env")[0]
    booked = next(c for c in profile["components"] if c["slug"] == "booked")
    assert booked["version"] is None
    assert booked["confidence"] == "low"


# ─────────────────────────────────────────────── 선별 근거

def test_selection_basis_records_evidence(conn, collected):
    selection = svc.select_templates(conn, [collected])
    basis = selection.basis

    slugs = {m["slug"] for m in basis["matched_components"]}
    assert "contact-form-7" in slugs
    assert all(m["templates"] for m in basis["matched_components"])
    assert {"product": "WordPress", "version": "6.4.2", "templates": []} in \
        basis["matched_stack"]
    assert "wordpress" in basis["selection_tags"]
    # 분모는 로컬 인벤토리. M5 전에는 0 이며 그 사실을 근거에 남긴다
    assert basis["universe"] == "templates"
    assert basis["total_available"] == env_repo.local_template_count(conn)
    assert basis["candidate_templates"] > 0


def test_selection_only_runs_templates_in_inventory(conn, collected):
    """인벤토리에 있는 것만 실행 대상. 없는 id 를 nuclei 에 넘기지 않는다"""
    conn.execute(
        "INSERT OR IGNORE INTO templates"
        " (template_id, source, file_path, name) VALUES"
        " ('wp-contact-form-7-fpd', 'official', 'x.yaml', 'CF7 FPD')"
    )
    conn.commit()
    try:
        selection = svc.select_templates(conn, [collected])
        assert selection.template_ids == ["wp-contact-form-7-fpd"]
        assert selection.basis["total_selected"] == 1
        assert selection.basis["total_available"] == 1
    finally:
        conn.execute("DELETE FROM templates WHERE template_id = 'wp-contact-form-7-fpd'")
        conn.commit()


def test_selection_basis_persisted_on_scan(conn, collected):
    from app.repository import scans as scan_repo

    selection = svc.select_templates(conn, [collected])
    scan_repo.set_selection_basis(conn, "scn_env", selection.basis)
    view = scan_repo.get_scan(conn, "scn_env")
    assert view["selection_basis"]["universe"] == "templates"
    assert view["template_selection"]["mode"] == "environment_driven"


# ─────────────────────────────────────────────── nuclei 인자 조립

def test_template_ids_use_id_flag_not_t():
    """-t 는 경로, -id 는 템플릿 id 필터다. id 를 -t 로 넘기면 경로로 해석되어 실패"""
    from app.adapters.nuclei import runner

    command = runner.build_command(
        runner.RunOptions(
            targets=["http://wp.local"],
            template_ids=["CVE-2026-33017", "wp-contact-form-7-fpd"],
            template_paths=["templates/custom"],
            tags=["wordpress"],
        ),
        exe="/usr/bin/nuclei",
    )
    assert "-id" in command
    assert command[command.index("-id") + 1] == "CVE-2026-33017,wp-contact-form-7-fpd"
    assert command[command.index("-t") + 1] == "templates/custom"
    assert "CVE-2026-33017" not in command[command.index("-t") + 1]

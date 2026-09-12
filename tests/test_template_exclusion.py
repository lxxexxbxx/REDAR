"""제외 계산. 한 건이라도 잘못 제외하면 미탐지. 유지 쪽 후퇴를 검증"""
from __future__ import annotations

from app.domain import template_exclusion as te

M = te.TemplateMeta


def _meta(tid, platform=None, path=None, tags=(), source="official"):
    return M(tid, path or f"/t/official/http/cves/{tid}.yaml", source, tuple(tags), platform)


DETECTORS = [
    _meta("joomla-detect", "joomla", "/t/official/http/technologies/joomla-detect.yaml", ("tech",)),
    _meta("apache-detect", "http_server", "/t/official/http/technologies/apache-detect.yaml", ("tech",)),
    _meta("wordpress-detect", "wordpress", "/t/official/http/technologies/wordpress-detect.yaml", ("tech",)),
    _meta("adminer-panel", "adminer", "/t/official/http/exposed-panels/adminer-panel.yaml", ("panel",)),
]
WP_ENV = te.TargetEnv(frozenset({"wordpress", "php"}), True)


def test_excludes_observable_undetected_product():
    plan = te.decide([*DETECTORS, _meta("cve-joomla", "joomla")], [WP_ENV])
    assert [m.template_id for m in plan.excluded] == ["cve-joomla"]
    assert plan.by_platform() == [{"platform": "joomla", "templates": 1}]
    assert plan.fallback_reason is None


def test_unobservable_product_is_kept():
    """detection 템플릿이 없는 제품은 탐지될 수 없음. 제외하면 영영 안 돌아감"""
    plan = te.decide([*DETECTORS, _meta("cve-struts", "struts")], [WP_ENV])
    assert plan.excluded == ()


def test_server_layer_is_kept_even_if_undetected():
    """리버스 프록시 뒤 백엔드는 앞단에서 안 보임"""
    plan = te.decide([*DETECTORS, _meta("cve-apache", "http_server")],
                     [te.TargetEnv(frozenset({"wordpress", "nginx"}), True)])
    assert plan.excluded == ()


def test_detected_product_is_kept_by_partial_match():
    plan = te.decide([*DETECTORS, _meta("cve-wp", "wordpress")], [WP_ENV])
    assert plan.excluded == ()


def test_panel_detected_product_is_kept():
    """같은 호스트의 /adminer.php 는 panels 사전 패스가 찾음. 찾으면 유지"""
    env = te.TargetEnv(frozenset({"wordpress", "adminer"}), True)
    plan = te.decide([*DETECTORS, _meta("cve-adminer", "adminer")], [env])
    assert plan.excluded == ()


def test_no_application_falls_back_to_all():
    plan = te.decide([*DETECTORS, _meta("cve-joomla", "joomla")],
                     [te.TargetEnv(frozenset({"nginx"}), False)])
    assert plan.excluded == ()
    assert plan.fallback_reason == "no_application"


def test_multi_target_keeps_union():
    """nuclei 1회 실행에 템플릿 집합은 하나. 한 대상이라도 필요하면 유지"""
    joomla_env = te.TargetEnv(frozenset({"joomla"}), True)
    plan = te.decide([*DETECTORS, _meta("cve-joomla", "joomla")], [WP_ENV, joomla_env])
    assert plan.excluded == ()


def test_empty_index_falls_back():
    assert te.decide([], [WP_ENV]).fallback_reason == "no_index"


def test_custom_and_unmarked_never_excluded():
    plan = te.decide(
        [*DETECTORS, _meta("mine", "joomla", source="custom"), _meta("generic", None)],
        [WP_ENV],
    )
    assert plan.excluded == ()


def test_prepass_membership():
    assert te.is_prepass(DETECTORS[0])
    assert te.is_prepass(DETECTORS[3])
    assert te.is_prepass(_meta("x", tags=("tech",)))
    assert not te.is_prepass(_meta("cve-x", "joomla"))
    assert not te.is_prepass(_meta("mine", tags=("tech",), source="custom"))
    # Windows 경로 구분자도 같은 판정
    assert te.is_prepass(_meta("w", path="C:\\t\\official\\http\\technologies\\w.yaml"))


def test_main_pass_files_skip_and_keep_unindexed(tmp_path):
    root = tmp_path / "official"
    for rel in ("http/cves/a.yaml", "http/cves/b.yaml", "http/new/unindexed.yaml",
                "helpers/x.yaml", "profiles/p.yml", ".git/c.yaml"):
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("id: x", encoding="utf-8")
    skip = {te.normalize_path(str(root / "http/cves/b.yaml"))}
    files = {te.normalize_path(p) for p in te.main_pass_files(root, skip)}
    assert files == {
        te.normalize_path(str(root / "http/cves/a.yaml")),
        te.normalize_path(str(root / "http/new/unindexed.yaml")),
    }


def test_main_pass_files_missing_dir(tmp_path):
    assert te.main_pass_files(tmp_path / "none", set()) == []

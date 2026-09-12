"""nuclei detection -> 환경 프로필. LLM 조치 가이드 입력이므로 버전 정확도가 핵심"""
from __future__ import annotations

from app.domain import tech_profile as tp

H = tp.DetectionHit


def test_wordpress_core_apache_php():
    profile = tp.build([
        H("wordpress-detect", None, ("6.4.2",), "wordpress", ("tech", "wordpress"), None),
        H("apache-detect", None, ("Apache/2.4.52 (Ubuntu)",), "http_server", ("tech",), None),
        H("php-detect", None, ("8.3.31",), "php", ("tech",), None),
    ])
    assert profile.stack["application"]["product"] == "wordpress"
    assert profile.stack["application"]["version"] == "6.4.2"
    assert profile.stack["web_server"]["version"] == "2.4.52"
    assert profile.stack["language"]["product"] == "php"
    assert {"wordpress", "http_server", "php"} <= profile.detected
    assert profile.app_identified


def test_plugin_version_and_outdated_flag():
    profile = tp.build([
        H("wordpress-litespeed-cache", "outdated_version", ("6.3.0.1",), "wordpress",
          ("tech", "wordpress", "wp-plugin"), "litespeed-cache"),
    ])
    comp = profile.components[0]
    assert (comp["type"], comp["slug"], comp["version"]) == ("wp_plugin", "litespeed-cache", "6.3.0.1")
    assert comp["confidence"] == "high"
    assert "최신" in comp["evidence"]


def test_generic_plugin_detector_uses_matcher_as_slug():
    profile = tp.build([
        H("wordpress-plugin-detect", "elementor", (), "wordpress", ("tech", "wp-plugin"), None),
        H("wordpress-theme-detect", "astra", (), "wordpress", ("tech", "wp-theme"), None),
    ])
    kinds = {(c["type"], c["slug"]) for c in profile.components}
    assert kinds == {("wp_plugin", "elementor"), ("wp_theme", "astra")}


def test_tech_detect_only_enriches_never_identifies_app():
    """Wappalyzer 매칭(jquery 등)만으로 애플리케이션 확정 금지. 확정되면 제외가 발동"""
    profile = tp.build([H("tech-detect", "jquery", (), None, ("tech",), None)])
    assert "jquery" in profile.detected
    assert not profile.app_identified
    assert profile.components[0]["type"] == "tech"


def test_cms_preferred_as_application():
    profile = tp.build([
        H("grafana-detect", None, ("10.1.0",), "grafana", ("tech",), None),
        H("wordpress-detect", None, (), "wordpress", ("tech",), None),
    ])
    assert profile.stack["application"]["product"] == "wordpress"
    assert any(c["slug"] == "grafana" for c in profile.components)


def test_versioned_hit_wins_over_versionless_duplicate():
    profile = tp.build([
        H("wordpress-detect", None, (), "wordpress", ("tech",), None),
        H("wordpress-version", None, ("6.9.4",), "wordpress", ("tech",), None),
    ])
    assert profile.stack["application"]["version"] == "6.9.4"


def test_empty_hits():
    profile = tp.build([])
    assert profile.stack == {} and profile.components == [] and not profile.app_identified

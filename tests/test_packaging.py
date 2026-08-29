"""M10 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M10).

번들 실행은 CI 에서 돌리지 않는다. 여기서는 경로 분리 규칙과 스펙 내용을 검증한다 -
번들 디렉터리에 쓰면 재시작 시 데이터가 소실된다
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from app.config import settings

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "packaging" / "backend.spec"
ENTRYPOINT = ROOT / "packaging" / "entrypoint.py"
BUILD = ROOT / "packaging" / "build.py"
TAURI_MAIN = ROOT / "src-tauri" / "src" / "main.rs"
TAURI_CONF = ROOT / "src-tauri" / "tauri.conf.json"


def _load_build():
    spec = importlib.util.spec_from_file_location("redar_build", BUILD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ─────────────────────────────── 경로 분리 (완료 조건 3)

def test_read_only_and_writable_paths_are_separate():
    """번들 리소스와 사용자 데이터가 같은 트리에 있으면 재시작 시 소실된다"""
    read_only = {
        settings.SCHEMA_PATH, settings.DATA_DIR, settings.FONTS_DIR,
        settings.FRONTEND_DIR, settings.MIGRATIONS_DIR,
    }
    writable = {settings.DB_PATH, settings.REPORTS_DIR, settings.TEMPLATES_DIR}
    assert read_only & writable == set()


def test_user_data_dir_is_platform_specific_when_frozen(monkeypatch):
    monkeypatch.setattr(settings, "FROZEN", True)
    monkeypatch.delenv("REDAR_HOME", raising=False)

    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", "/tmp/localappdata")
    assert settings.user_data_dir() == Path("/tmp/localappdata/REDAR")

    monkeypatch.setattr("sys.platform", "darwin")
    assert settings.user_data_dir() == Path.home() / ".redar"


def test_dev_run_uses_repository_root(monkeypatch):
    """개발과 배포에서 경로가 갈리면 동작이 달라진다"""
    monkeypatch.setattr(settings, "FROZEN", False)
    monkeypatch.delenv("REDAR_HOME", raising=False)
    assert settings.user_data_dir() == ROOT


def test_redar_home_override(monkeypatch, tmp_path):
    monkeypatch.setenv("REDAR_HOME", str(tmp_path / "custom"))
    # resolve() 를 거치므로 심볼릭 링크가 풀린 경로와 비교한다
    assert settings.user_data_dir() == (tmp_path / "custom").resolve()


def test_resource_path_follows_bundle_root():
    assert settings.resource_path("db/schema.sql") == settings.SCHEMA_PATH
    assert settings.SCHEMA_PATH.is_file()


def test_bundled_nuclei_preferred_when_frozen(monkeypatch, tmp_path):
    monkeypatch.delenv("REDAR_NUCLEI", raising=False)
    monkeypatch.setattr(settings, "FROZEN", True)
    monkeypatch.setattr(settings, "ROOT", tmp_path)
    binary = tmp_path / "bin" / "nuclei"
    binary.parent.mkdir()
    binary.write_text("#!/bin/sh\n")
    monkeypatch.setattr("sys.platform", "darwin")
    assert settings.nuclei_bin() == str(binary)


def test_nuclei_env_override_wins(monkeypatch):
    monkeypatch.setenv("REDAR_NUCLEI", "/custom/nuclei")
    assert settings.nuclei_bin() == "/custom/nuclei"


# ─────────────────────────────── PyInstaller 스펙

def test_spec_uses_onedir_not_onefile():
    """onefile 은 매 실행 압축 해제로 5~15초 지연이 생긴다"""
    text = SPEC.read_text(encoding="utf-8")
    assert "COLLECT(" in text
    assert "exclude_binaries=True" in text


def test_spec_bundles_read_only_resources():
    text = SPEC.read_text(encoding="utf-8")
    for needed in ("schema.sql", '"data"', "assets", "frontend",
                   "app/report/templates", "severity_map.yaml"):
        assert needed in text, needed


def test_spec_lists_dynamic_imports():
    """수집기·LLM Provider 는 동적 import 라 정적 분석이 놓친다"""
    text = SPEC.read_text(encoding="utf-8")
    for module in ("app.collectors.wordpress", "app.collectors.generic_http",
                   "app.collectors.apache", "app.adapters.llm.monogpt"):
        assert module in text, module


def test_spec_disables_upx():
    """UPX 압축은 백신 오탐을 늘린다"""
    assert "upx=False" in SPEC.read_text(encoding="utf-8")


def test_collectors_registry_matches_spec_hidden_imports():
    """수집기를 추가하고 스펙에 넣지 않으면 번들에서 조용히 사라진다"""
    from app.collectors import base as collectors

    text = SPEC.read_text(encoding="utf-8")
    for collector in collectors.registry():
        module = collector.__class__.__module__
        assert module in text, f"{module} 이 backend.spec 에 없다"


# ─────────────────────────────── 진입점 (완료 조건 5)

def test_entrypoint_uses_dynamic_port():
    """고정 포트는 점유 시 기동 실패하거나 타 프로세스에 접속한다"""
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert "free_port" in text
    assert 'bind(("127.0.0.1", 0))' in text


def test_entrypoint_passes_app_object_not_import_string():
    """번들에서는 uvicorn 이 'app.main:app' 을 다시 import 하지 못한다"""
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert 'uvicorn.run(\n        asgi_app' in text
    assert '"app.main:app"' not in text


def test_entrypoint_creates_db_on_first_run():
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert "init_db(settings.DB_PATH)" in text
    assert "settings.HOME.mkdir" in text


def test_entrypoint_announces_ready_line():
    """Tauri 셸이 이 한 줄을 읽어 WebView 를 띄운다"""
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert 'READY_PREFIX = "REDAR_READY "' in text
    assert "flush=True" in text


def test_free_port_returns_bindable_port():
    import socket

    module = importlib.util.spec_from_file_location("entry", ENTRYPOINT)
    entry = importlib.util.module_from_spec(module)
    module.loader.exec_module(entry)

    port = entry.free_port()
    assert 1024 < port < 65536
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))       # 실제로 바인딩 가능해야 한다


def test_two_runs_get_different_ports():
    """두 번 실행해도 포트 충돌이 없어야 한다 (완료 조건 5)"""
    import socket

    module = importlib.util.spec_from_file_location("entry2", ENTRYPOINT)
    entry = importlib.util.module_from_spec(module)
    module.loader.exec_module(entry)

    with socket.socket() as held:
        held.bind(("127.0.0.1", 0))
        taken = held.getsockname()[1]
        assert entry.free_port() != taken


# ─────────────────────────────── Tauri 셸 (완료 조건 4)

def test_tauri_kills_sidecar_on_exit():
    """앱 종료 후 redar-backend 프로세스가 남으면 포트와 DB 락이 유지된다"""
    text = TAURI_MAIN.read_text(encoding="utf-8")
    assert "child.kill()" in text
    assert "WindowEvent::Destroyed" in text


def test_tauri_reads_port_from_sidecar_stdout():
    text = TAURI_MAIN.read_text(encoding="utf-8")
    assert 'READY_PREFIX: &str = "REDAR_READY "' in text
    assert "CommandEvent::Stdout" in text
    assert "127.0.0.1" in text


def test_tauri_sidecar_name_matches_build_script():
    conf = TAURI_CONF.read_text(encoding="utf-8")
    assert "binaries/redar-backend" in conf
    assert _load_build().BACKEND_NAME == "redar-backend"


def test_target_triple_is_appended_to_sidecar_name():
    """트리플이 없으면 Tauri 가 sidecar 를 찾지 못한다"""
    build = _load_build()
    triple = build.target_triple()
    assert re.match(r"^[\w]+-[\w.-]+$", triple), triple
    assert "-" in triple


# ─────────────────────────────── 빌드 스크립트 (완료 조건 1)

def test_build_script_runs_three_stages_in_order():
    text = BUILD.read_text(encoding="utf-8")
    assert text.index("build_backend") < text.index("stage_sidecar")
    assert text.index("stage_sidecar") < text.index("build_tauri")


def test_build_script_fails_loudly_without_toolchain(monkeypatch):
    build = _load_build()
    monkeypatch.setattr(build.shutil, "which", lambda name: None)
    with pytest.raises(SystemExit, match="cargo"):
        build.build_tauri()


def test_pdf_is_derived_not_generated():
    """PDF 는 WebView 인쇄로 파생시킨다. 네이티브 렌더러를 넣지 않는다 (절대규칙 4-1)"""
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    for banned in ("weasyprint", "wkhtmltopdf", "pdfkit", "reportlab", "fpdf"):
        assert banned not in text, banned

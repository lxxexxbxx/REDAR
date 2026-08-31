"""M10 완료 조건 검증 (IMPLEMENTATION_BRIEF.md M10).

번들 실행은 CI 에서 돌리지 않음. 여기서는 경로 분리 규칙과 스펙 내용을 검증 -
번들 디렉터리에 쓰면 재시작 시 데이터가 소실됨
"""
from __future__ import annotations

import importlib.util
import json
import sys
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
    """번들 리소스와 사용자 데이터가 같은 트리에 있으면 재시작 시 소실됨"""
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
    """개발과 배포에서 경로가 갈리면 동작이 달라짐"""
    monkeypatch.setattr(settings, "FROZEN", False)
    monkeypatch.delenv("REDAR_HOME", raising=False)
    assert settings.user_data_dir() == ROOT


def test_redar_home_override(monkeypatch, tmp_path):
    monkeypatch.setenv("REDAR_HOME", str(tmp_path / "custom"))
    # resolve() 를 거치므로 심볼릭 링크가 풀린 경로와 비교함
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
    """onefile 은 매 실행 압축 해제로 5~15초 지연이 생김"""
    text = SPEC.read_text(encoding="utf-8")
    assert "COLLECT(" in text
    assert "exclude_binaries=True" in text


def test_spec_bundles_data_csv_without_captures():
    """번들 대상은 data/*.csv 개별 지정. guide_images/ 는 미채택이라 제외"""
    # 주석은 근거이므로 본문 전체가 아니라 실제 항목만 봄
    entries = [
        line.strip() for line in SPEC.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith(("(str(ROOT", '"'))
    ]
    joined = " ".join(entries)
    assert 'ROOT / "data"), "data"' not in joined     # 통째 포함 금지
    assert "guide_images" not in joined
    for bundled in ("vuln_type_rules.csv", "guide_mappings.csv",
                    "component_advisories.csv", "settings_defaults.csv",
                    "guide_items_2026.csv"):
        assert bundled in joined, bundled


def test_spec_bundles_read_only_resources():
    text = SPEC.read_text(encoding="utf-8")
    for needed in ("schema.sql", '"data"', "assets", "frontend",
                   "app/report/templates", "severity_map.yaml"):
        assert needed in text, needed


def test_spec_lists_dynamic_imports():
    """수집기·LLM Provider 는 동적 import 라 정적 분석이 놓침"""
    text = SPEC.read_text(encoding="utf-8")
    for module in ("app.collectors.wordpress", "app.collectors.generic_http",
                   "app.collectors.apache", "app.adapters.llm.monogpt"):
        assert module in text, module


def test_spec_disables_upx():
    """UPX 압축은 백신 오탐을 늘림"""
    assert "upx=False" in SPEC.read_text(encoding="utf-8")


def test_collectors_registry_matches_spec_hidden_imports():
    """수집기를 추가하고 스펙에 넣지 않으면 번들에서 조용히 사라짐"""
    from app.collectors import base as collectors

    text = SPEC.read_text(encoding="utf-8")
    for collector in collectors.registry():
        module = collector.__class__.__module__
        assert module in text, f"{module} 이 backend.spec 에 없다"


# ─────────────────────────────── 진입점 (완료 조건 5)

def test_entrypoint_uses_dynamic_port():
    """고정 포트는 점유 시 기동 실패하거나 타 프로세스에 접속"""
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert "free_port" in text
    assert 'bind(("127.0.0.1", 0))' in text


def test_entrypoint_passes_app_object_not_import_string():
    """번들에서는 uvicorn 이 'app.main:app' 을 다시 import 하지 못"""
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert 'uvicorn.run(\n        asgi_app' in text
    assert '"app.main:app"' not in text


def test_entrypoint_creates_db_on_first_run():
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert "init_db(settings.DB_PATH)" in text
    assert "settings.HOME.mkdir" in text


def test_entrypoint_announces_ready_line():
    """Tauri 셸이 이 한 줄을 읽어 WebView 를 띄움"""
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
    """앱 종료 후 redar-backend 프로세스가 남으면 포트와 DB 락이 유지됨"""
    text = TAURI_MAIN.read_text(encoding="utf-8")
    assert text.count("child.kill()") == 2       # 창 파괴 + 앱 종료 양쪽
    assert "WindowEvent::Destroyed" in text
    assert "RunEvent::Exit" in text


def test_backend_exits_when_parent_dies():
    """셸이 강제 종료되면 창 이벤트가 돌지 않음. 백엔드가 스스로 빠져야 한다"""
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert "watch_parent()" in text
    assert "sys.stdin.readline()" in text
    assert "os._exit(0)" in text


def test_tauri_reads_port_from_sidecar_stdout():
    text = TAURI_MAIN.read_text(encoding="utf-8")
    assert 'READY_PREFIX: &str = "REDAR_READY "' in text
    assert "CommandEvent::Stdout" in text
    assert "127.0.0.1" in text


def test_backend_bundled_as_directory_resource():
    """externalBin 은 파일 하나만 복사해 --onedir 의 _internal 이 빠짐"""
    conf = json.loads(TAURI_CONF.read_text(encoding="utf-8"))
    assert "externalBin" not in conf["bundle"]
    # 심볼릭 링크를 푼 복사본을 넣음 (packaging/build.py stage_backend)
    # 배열 형태여야 상대 경로 구조가 보존됨. 맵 형태는 평탄화함
    assert conf["bundle"]["resources"] == ["backend/**/*"]
    assert _load_build().BACKEND_NAME == "redar-backend"


def test_tauri_resolves_backend_from_resource_dir():
    text = TAURI_MAIN.read_text(encoding="utf-8")
    assert "resource_dir()" in text
    assert '.join("backend")' in text           # resources 배열이 보존하는 경로
    assert "redar-backend.exe" in text          # Windows 확장자 분기
    assert ".sidecar(" not in text


def test_stage_backend_dereferences_symlinks(tmp_path, monkeypatch):
    """Python.framework 의 심볼릭 링크에서 Tauri 리소스 복사가 실패"""
    build = _load_build()
    source = tmp_path / "dist" / "redar-backend"
    (source / "_internal" / "Python.framework").mkdir(parents=True)
    (source / "redar-backend").write_text("#!/bin/sh\n")
    versions = source / "_internal" / "Python.framework" / "Versions"
    (versions / "3.12").mkdir(parents=True)
    (versions / "3.12" / "Python").write_text("lib")
    # Current -> 3.12. 자기 참조가 아니라 형제 디렉터리를 가리킴
    (versions / "Current").symlink_to(versions / "3.12", target_is_directory=True)

    stage = tmp_path / "stage"
    monkeypatch.setattr(build, "STAGE_DIR", stage)
    monkeypatch.setattr(build.platform, "system", lambda: "Darwin")
    build.stage_backend(source)

    assert (stage / "redar-backend").is_file()
    assert [p for p in stage.rglob("*") if p.is_symlink()] == []


def test_spec_has_no_onefile_branch():
    """onefile 은 실행마다 9~18초가 걸림 (onedir 0.3초. 실측)"""
    text = SPEC.read_text(encoding="utf-8")
    assert "ONEFILE" not in text
    assert "COLLECT(" in text


# ─────────────────────────────── 앱 아이콘

def test_bundle_icons_cover_platform_formats():
    """PNG 만 등록하면 macOS 번들이 'No matching IconType' 로 실패.
    플랫폼별 컨테이너를 함께 등록해야 함"""
    conf = json.loads((ROOT / "src-tauri" / "tauri.conf.json").read_text("utf-8"))
    icons = conf["bundle"]["icon"]
    suffixes = {Path(i).suffix for i in icons}
    assert ".icns" in suffixes, "macOS 번들에 icns 필요"
    assert ".ico" in suffixes, "Windows 번들에 ico 필요"
    assert ".png" in suffixes
    for entry in icons:
        assert (ROOT / "src-tauri" / entry).is_file(), entry


def test_ico_holds_small_sizes():
    """작업 표시줄·탭 아이콘은 16·32 를 씀. 큰 이미지 하나만 넣으면 뭉개짐"""
    raw = (ROOT / "src-tauri" / "icons" / "icon.ico").read_bytes()
    count = int.from_bytes(raw[4:6], "little")
    assert count >= 4
    # 디렉터리 엔트리의 첫 바이트가 가로 크기. 256 은 규격상 0
    widths = {raw[6 + 16 * i] or 256 for i in range(count)}
    assert {16, 32}.issubset(widths), widths


# ─────────────────────────────── 빌드 스크립트 (완료 조건 1)

def test_build_script_runs_three_stages_in_order():
    text = BUILD.read_text(encoding="utf-8")
    assert text.index("build_backend") < text.index("stage_backend")
    assert text.index("stage_backend") < text.index("build_tauri")


def test_build_script_fails_loudly_without_toolchain(monkeypatch):
    """자동 설치를 요청하지 않았으면 OS 별 설치 방법을 안내하고 멈춤"""
    build = _load_build()
    monkeypatch.setattr(build, "cargo_path", lambda: None)
    with pytest.raises(SystemExit) as exc:
        build.build_tauri(False)
    message = str(exc.value)
    assert "rustup" in message
    for platform_name in ("Windows", "macOS", "Linux"):
        assert platform_name in message
    assert "--no-auto-install" in message


def test_msvc_checked_before_compiling(monkeypatch):
    """링커가 없으면 크레이트 수백 개를 받아 컴파일한 끝에서 실패한다.
    시작 전에 잡아야 다운로드·컴파일 시간을 버리지 않음"""
    build = _load_build()
    monkeypatch.setattr(build.platform, "system", lambda: "Windows")
    monkeypatch.setattr(build, "cargo_path", lambda: "C:/cargo.exe")
    monkeypatch.setattr(build, "msvc_linker", lambda: None)
    called: list[str] = []
    monkeypatch.setattr(build, "ensure_node", lambda auto: called.append("node") or "")

    with pytest.raises(SystemExit) as exc:
        build.build_tauri(True)
    message = str(exc.value)
    assert "link.exe" in message
    assert "VCTools" in message              # 정확한 설치 명령을 알려줌
    assert called == []                      # 빌드 단계로 넘어가지 않음


def test_msvc_check_skipped_off_windows(monkeypatch):
    build = _load_build()
    monkeypatch.setattr(build.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(build, "cargo_path", lambda: "/usr/bin/cargo")
    monkeypatch.setattr(build, "msvc_linker", lambda: None)
    monkeypatch.setattr(build, "ensure_node", lambda auto: "/usr/bin/npx")
    ran: list[list[str]] = []
    monkeypatch.setattr(build, "run", lambda cmd, **kw: ran.append(cmd))

    build.build_tauri(True)
    assert ran, "macOS 에서는 MSVC 검사로 막히지 않아야 함"


def test_artifact_paths_reported_per_platform(monkeypatch, tmp_path, capsys):
    """플랫폼마다 산출물 경로가 달라 어디를 봐야 할지 알기 어려움"""
    build = _load_build()
    monkeypatch.setattr(build, "ROOT", tmp_path)
    monkeypatch.setattr(build.platform, "system", lambda: "Windows")
    release = tmp_path / "src-tauri" / "target" / "release"
    (release / "bundle" / "msi").mkdir(parents=True)
    (release / "redar.exe").write_text("x", encoding="utf-8")
    (release / "bundle" / "msi" / "REDAR_0.3.0_x64.msi").write_text("x", encoding="utf-8")

    build.report_artifacts()
    out = capsys.readouterr().out
    assert "redar.exe" in out
    assert "REDAR_0.3.0_x64.msi" in out


def test_build_script_installs_rust_only_when_asked(monkeypatch):
    """빌드가 임의로 툴체인을 설치하지 않음. 옵션이 있어야 한다"""
    build = _load_build()
    calls: list[str] = []
    monkeypatch.setattr(build, "cargo_path", lambda: None)
    monkeypatch.setattr(build, "install_rust", lambda: calls.append("install") or "")

    with pytest.raises(SystemExit):
        build.build_tauri(False)
    assert calls == []


def test_pdf_is_derived_not_generated():
    """PDF 는 WebView 인쇄로 파생. 네이티브 렌더러를 넣지 않음 (절대규칙 4-1)"""
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    for banned in ("weasyprint", "wkhtmltopdf", "pdfkit", "reportlab", "fpdf"):
        assert banned not in text, banned


# ─────────────────────────────── nuclei 설치 스크립트 (tools/install_nuclei.py)

INSTALLER = ROOT / "tools" / "install_nuclei.py"


def _load_installer():
    spec = importlib.util.spec_from_file_location("redar_install_nuclei", INSTALLER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_installer_uses_go_install_not_bundled_binary():
    """저장소·번들에 바이너리를 넣지 않음. go install 로 사용자가 빌드"""
    installer = _load_installer()
    assert installer.NUCLEI_PKG == (
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )
    # go install 로 빌드. 미리 컴파일된 바이너리를 받아오지 않음
    assert '"install", "-v", NUCLEI_PKG' in INSTALLER.read_text(encoding="utf-8")


def test_install_path_is_registered_as_outbound_endpoint():
    """자동 설치는 외부 통신 지점 4번. 목록에 없으면 통제 밖에서 통신"""
    from app.repository import settings_repo

    assert "dependency_install" in settings_repo.EXTERNAL_ENDPOINT_KEYS


def test_installer_verifies_checksum_before_extracting():
    """검증 실패한 아카이브를 풀지 않음"""
    source = INSTALLER.read_text(encoding="utf-8")
    download = source.split("def download(")[1].split("def extract(")[0]
    assert "sha256" in download
    assert "체크섬 불일치" in download
    assert "unlink" in download


def test_installer_extract_blocks_path_traversal():
    source = INSTALLER.read_text(encoding="utf-8")
    assert 'filter="data"' in source


def test_installer_install_path_matches_app_lookup():
    """설치 경로와 앱 탐색 경로가 어긋나면 설치해도 찾지 못"""
    installer = _load_installer()
    expected = settings.platform_home() / "bin"
    assert installer.BIN_DIR == expected


def test_version_of_skips_warning_lines():
    """nuclei 는 환경에 따라 경고를 먼저 낸다. 첫 줄만 보면 버전 대신 경고가 나옴"""
    installer = _load_installer()
    sample = (
        "WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU)\n"
        "\x1b[34m[INF]\x1b[0m Nuclei Engine Version: v3.11.1\n"
    )
    lines = [
        installer._ANSI.sub("", line).strip()
        for line in sample.splitlines() if line.strip()
    ]
    picked = next(
        line for line in lines
        if not line.upper().startswith("WARNING")
        and installer._VERSION_LINE.search(line)
    )
    assert "v3.11.1" in picked
    assert "WARNING" not in picked


def test_nuclei_invocations_close_stdin():
    """대상 인자가 없으면 nuclei 가 stdin 을 읽으려 대기. 파이프면 무한 대기"""
    targets = [
        ROOT / "app" / "services" / "template_validator.py",
        ROOT / "app" / "services" / "template_service.py",
        ROOT / "app" / "adapters" / "nuclei" / "version_check.py",
        ROOT / "app" / "adapters" / "nuclei" / "runner.py",
    ]
    for path in targets:
        assert "stdin=subprocess.DEVNULL" in path.read_text(encoding="utf-8"), path


def test_builder_requires_author_field():
    """nuclei 는 info.author 를 필수로 요구 (no template author field provided)"""
    from app.services import template_builder

    author = next(
        field
        for section in template_builder.FORM_SCHEMA["sections"]
        if section["key"] == "info"
        for field in section["fields"]
        if field["key"] == "author"
    )
    assert author["required"] is True


# ─────────────────────────────── 원클릭 빌드

def test_build_bootstraps_venv_and_reexecutes():
    """시스템 파이썬으로 PyInstaller 를 돌리면 의존성이 번들에서 빠짐"""
    text = BUILD.read_text(encoding="utf-8")
    assert "def ensure_venv()" in text
    assert '"-m", "venv"' in text
    assert 'str(REQUIREMENTS)' in text
    assert "in_target_venv()" in text


def test_build_reexec_does_not_recurse(monkeypatch):
    """재실행된 자식이 다시 재실행하면 무한 루프"""
    build = _load_build()
    calls: list[list[str]] = []
    monkeypatch.setattr(build.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd))
    monkeypatch.setattr(build, "ensure_deps", lambda python: None)
    assert build.in_target_venv() is True        # 테스트는 venv 안에서 돔
    build.ensure_venv()
    assert calls == []                           # 재실행하지 않음


def test_build_installs_deps_even_inside_venv(monkeypatch):
    """가상환경을 먼저 활성화하고 실행하면 설치가 통째로 빠져
    'PyInstaller 가 없습니다' 로 끝났음"""
    build = _load_build()
    installed: list[str] = []
    monkeypatch.setattr(build, "ensure_deps",
                        lambda python: installed.append(python))
    build.ensure_venv()
    assert installed == [sys.executable]


def test_node_installed_in_one_run(monkeypatch):
    """node 가 없다고 빌드가 끝나면 사용자가 두 번 실행해야 함"""
    build = _load_build()
    monkeypatch.setattr(build, "npx_path", lambda: None)
    monkeypatch.setattr(build, "install_node", lambda: "/tmp/npx")
    assert build.ensure_node(True) == "/tmp/npx"
    with pytest.raises(SystemExit) as exc:
        build.ensure_node(False)
    assert "nodejs.org" in str(exc.value)


def test_node_archive_checksum_verified_before_extract():
    """검증 없이 풀면 변조된 아카이브가 그대로 실행됨"""
    text = BUILD.read_text(encoding="utf-8")
    body = text.split("def install_node()")[1].split("def ensure_node")[0]
    assert body.index("SHASUMS256.txt") < body.index("extractall")
    assert body.index("체크섬 불일치") < body.index("extractall")
    assert 'filter="data"' in body            # tar 경로 탈출 차단


def test_nuclei_bundled_into_same_run(monkeypatch):
    """nuclei 설치를 따로 실행하게 두면 원클릭이 아님"""
    build = _load_build()
    text = BUILD.read_text(encoding="utf-8")
    main = text.split("def main()")[1]
    assert "ensure_nuclei(" in main

    calls: list[list[str]] = []

    class _Done:
        returncode = 1

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return _Done()

    monkeypatch.setattr(build.subprocess, "run", fake_run)
    build.ensure_nuclei(True)
    assert len(calls) == 2                    # --check 후 설치
    assert "--check" in calls[0]
    assert "--check" not in calls[1]


def test_nuclei_not_installed_without_auto(monkeypatch, capsys):
    build = _load_build()

    class _Done:
        returncode = 1

    monkeypatch.setattr(build.subprocess, "run", lambda cmd, **kw: _Done())
    build.ensure_nuclei(False)
    assert "install_nuclei.py" in capsys.readouterr().out


def test_build_runs_full_pipeline_by_default():
    """clone 후 명령 하나로 GUI 까지 떠야 함"""
    text = BUILD.read_text(encoding="utf-8")
    main = text.split("def main()")[1]
    for stage in ("ensure_venv()", "build_backend(", "stage_backend(",
                  "build_tauri(", "launch()"):
        assert stage in main, stage
    # 전체 실행이 기본. 축소가 옵션
    assert "--backend-only" in main
    assert "--no-launch" in main


def test_launch_reports_when_binary_missing(monkeypatch, tmp_path, capsys):
    """실행 파일이 없어도 빌드 산출물은 남기고 경고만"""
    build = _load_build()
    monkeypatch.setattr(build, "ROOT", tmp_path)
    build.launch()
    assert "실행 파일을 찾지 못함" in capsys.readouterr().out

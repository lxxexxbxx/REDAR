"""의존성 관리 검증.

자동 설치는 외부 통신 지점 4번. 기본 비활성 · 오프라인 차단 ·
요청마다 명시 동의라는 세 겹의 통제가 실제로 동작해야 한다 (docs/01 §7.1).
반입·경로 지정은 통신이 없으므로 폐쇄망에서도 동작해야 함
"""
from __future__ import annotations

import os
import stat
from functools import lru_cache
from pathlib import Path

import pytest

from app.adapters.nuclei import version_check
from app.config import settings
from app.repository import settings_repo
from app.services import dependency_service
from app.services.scan_service import ScanError

API = "/api/v1"


@pytest.fixture
def home(tmp_path, monkeypatch):
    """설치·반입 경로를 임시 디렉터리로 격리"""
    monkeypatch.setattr(settings, "platform_home", lambda: tmp_path)
    yield tmp_path
    settings.set_configured_nuclei(None)


WINDOWS = dependency_service.WINDOWS
# Windows 는 nuclei.exe. 고정하면 반입 경로 단언이 헛돎
NUCLEI_FILE = dependency_service.get("nuclei").filename


@pytest.fixture
def fake_binary(tmp_path):
    """-version 에 응답하는 가짜 실행 파일. 확장자·형식은 플랫폼에 맞춤

    Windows 는 실행 권한 비트가 없고 확장자로 실행 가능 여부를 판정하므로
    sh 스크립트를 그대로 두면 경로 고정 자체가 거부됨
    """
    if WINDOWS:
        path = tmp_path / "fake-nuclei.cmd"
        path.write_text("@echo Nuclei Engine Version: v9.9.9\r\n", encoding="utf-8")
        return path
    path = tmp_path / "fake-nuclei"
    path.write_text(
        "#!/bin/sh\necho 'Nuclei Engine Version: v9.9.9'\n", encoding="utf-8"
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


@pytest.fixture
def probe_version(monkeypatch):
    """반입 경로의 버전 탐지 주입. Windows 에서만 동작

    반입은 payload 를 nuclei.exe 로 저장하는데 가짜는 실제 PE 가 아니라 실행 불가.
    OS 실행만 대체하고 반입·롤백·설정 저장 로직은 그대로 검증.
    POSIX 는 sh 스크립트가 실제로 돌기 때문에 손대지 않음
    """
    if not WINDOWS:
        return

    @lru_cache(maxsize=1)
    def fake() -> str | None:
        exe = settings.nuclei_bin()
        if not exe or not Path(exe).is_file():
            return None
        # 실행 불가 파일 롤백 테스트가 살아 있어야 하므로 내용을 확인
        return "9.9.9" if b"9.9.9" in Path(exe).read_bytes() else None

    monkeypatch.setattr(version_check, "version", fake)


@pytest.fixture
def clean_settings(conn):
    yield
    settings_repo.put_many(conn, {
        "offline_mode": True, "ext_dependency_install_enabled": False,
        "dep_nuclei_path": "",
    })
    settings.set_configured_nuclei(None)


# ─────────────────────────────── 자동 설치 통제 (외부 통신 4번)

def test_install_blocked_in_offline_mode(conn, clean_settings):
    settings_repo.put_many(conn, {
        "offline_mode": True, "ext_dependency_install_enabled": True,
    })
    with pytest.raises(ScanError) as exc:
        dependency_service.install(conn, "nuclei", confirmed=True)
    assert exc.value.status_code == 403
    assert exc.value.code == "OFFLINE_MODE_BLOCKED"


def test_install_blocked_when_endpoint_disabled(conn, clean_settings):
    settings_repo.put_many(conn, {
        "offline_mode": False, "ext_dependency_install_enabled": False,
    })
    with pytest.raises(ScanError) as exc:
        dependency_service.install(conn, "nuclei", confirmed=True)
    assert exc.value.status_code == 403


def test_install_requires_explicit_confirmation(conn, clean_settings):
    """설정만으로 자동 실행되지 않음. 요청마다 사용자가 동의"""
    settings_repo.put_many(conn, {
        "offline_mode": False, "ext_dependency_install_enabled": True,
    })
    with pytest.raises(ScanError) as exc:
        dependency_service.install(conn, "nuclei", confirmed=False)
    assert "동의" in exc.value.message


def test_confirmation_checked_before_network(conn, clean_settings, monkeypatch):
    """동의 없이는 네트워크에 닿기 전에 멈춤"""
    called: list[str] = []
    monkeypatch.setattr(
        dependency_service, "go_asset", lambda: called.append("net") or ("x", "")
    )
    settings_repo.put_many(conn, {
        "offline_mode": False, "ext_dependency_install_enabled": True,
    })
    with pytest.raises(ScanError):
        dependency_service.install(conn, "nuclei", confirmed=False)
    assert called == []


def test_offline_checked_before_network(conn, clean_settings, monkeypatch):
    called: list[str] = []
    monkeypatch.setattr(
        dependency_service, "go_asset", lambda: called.append("net") or ("x", "")
    )
    settings_repo.put_many(conn, {"offline_mode": True})
    with pytest.raises(ScanError):
        dependency_service.install(conn, "nuclei", confirmed=True)
    assert called == []


def test_install_endpoint_is_in_whitelist():
    assert "dependency_install" in settings_repo.EXTERNAL_ENDPOINT_KEYS


def test_unknown_dependency_rejected(conn):
    with pytest.raises(ScanError) as exc:
        dependency_service.get("wireshark")
    assert exc.value.status_code == 400


# ─────────────────────────────── 반입 (통신 없음. 폐쇄망 경로)

def test_import_works_offline(conn, home, fake_binary, probe_version,
                              clean_settings):
    """오프라인에서도 반입은 동작해야 한다. 폐쇄망의 유일한 경로"""
    settings_repo.put_many(conn, {"offline_mode": True})
    result = dependency_service.import_binary(
        conn, "nuclei", fake_binary.read_bytes()
    )
    entry = next(i for i in result["items"] if i["key"] == "nuclei")
    assert entry["available"] is True
    assert entry["source"] == "configured"
    assert (home / "bin" / NUCLEI_FILE).is_file()
    assert len(result["sha256"]) == 64


def test_imported_binary_is_executable(conn, home, fake_binary, probe_version,
                                       clean_settings):
    dependency_service.import_binary(conn, "nuclei", fake_binary.read_bytes())
    target = home / "bin" / NUCLEI_FILE
    # 판정 기준이 플랫폼마다 달라 서비스와 같은 술어를 씀 (Windows 는 확장자)
    assert dependency_service._is_executable(target)


def test_unrunnable_import_is_rejected_and_rolled_back(conn, home, clean_settings):
    """실행되지 않는 파일을 등록한 채로 두면 스캔이 조용히 실패"""
    with pytest.raises(ScanError, match="실행 불가"):
        dependency_service.import_binary(conn, "nuclei", b"not-a-binary")
    assert not (home / "bin" / NUCLEI_FILE).exists()
    assert not settings_repo.get_all(conn).get("dep_nuclei_path")


def test_empty_import_rejected(conn, home, clean_settings):
    with pytest.raises(ScanError, match="빈 파일"):
        dependency_service.import_binary(conn, "nuclei", b"")


# ─────────────────────────────── 경로 지정 (특정 버전 고정)

def test_set_path_pins_specific_binary(conn, home, fake_binary, clean_settings):
    result = dependency_service.set_path(conn, "nuclei", str(fake_binary))
    entry = next(i for i in result["items"] if i["key"] == "nuclei")
    assert entry["path"] == str(fake_binary)
    assert entry["source"] == "configured"
    # 지정 경로가 자동 탐색을 이김
    assert settings.nuclei_bin() == str(fake_binary)


def test_set_path_rejects_missing_file(conn, home, clean_settings):
    with pytest.raises(ScanError, match="파일 없음"):
        dependency_service.set_path(conn, "nuclei", "/nonexistent/nuclei")


def test_set_path_rejects_non_executable(conn, home, tmp_path, clean_settings):
    plain = tmp_path / "plain.txt"
    plain.write_text("x", encoding="utf-8")
    plain.chmod(0o644)
    with pytest.raises(ScanError, match="실행 권한"):
        dependency_service.set_path(conn, "nuclei", str(plain))


def test_clearing_path_restores_auto_detection(conn, home, fake_binary,
                                               clean_settings):
    dependency_service.set_path(conn, "nuclei", str(fake_binary))
    dependency_service.set_path(conn, "nuclei", None)
    assert not settings_repo.get_all(conn).get("dep_nuclei_path")


# ─────────────────────────────── 상태 조회

def test_status_reports_blocked_reason_when_offline(conn, home, clean_settings):
    settings_repo.put_many(conn, {"offline_mode": True})
    result = dependency_service.status(conn)
    assert result["install_allowed"] is False
    assert "오프라인" in result["blocked_reason"]
    assert "반입" in result["blocked_reason"]


def test_status_allows_install_when_enabled(conn, home, clean_settings):
    settings_repo.put_many(conn, {
        "offline_mode": False, "ext_dependency_install_enabled": True,
    })
    result = dependency_service.status(conn)
    assert result["install_allowed"] is True
    assert result["blocked_reason"] is None


def test_status_includes_manual_guidance(conn, home, clean_settings):
    """자동 설치를 거부한 사용자가 직접 준비할 수 있어야 한다"""
    entry = next(
        i for i in dependency_service.status(conn)["items"] if i["key"] == "nuclei"
    )
    assert entry["manual_url"].startswith("https://")
    assert entry["import_dir"]
    assert entry["required_for"]


# ─────────────────────────────── API

def test_dependency_endpoints(db_path, monkeypatch, home, fake_binary,
                              probe_version):
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.setattr("app.repository.db.settings.DB_PATH", db_path, raising=False)
    with TestClient(app) as client:
        listed = client.get(f"{API}/dependencies")
        assert listed.status_code == 200
        assert listed.json()["items"][0]["key"] == "nuclei"

        # 동의 없는 설치 요청은 거부됨
        denied = client.post(f"{API}/dependencies/nuclei/install", json={})
        assert denied.status_code in (400, 403)

        pinned = client.put(
            f"{API}/dependencies/nuclei/path", json={"path": str(fake_binary)}
        )
        assert pinned.status_code == 200

        imported = client.post(
            f"{API}/dependencies/nuclei/import",
            files={"file": ("nuclei", fake_binary.read_bytes())},
        )
        assert imported.status_code == 200

        client.put(f"{API}/dependencies/nuclei/path", json={"path": None})


def test_reported_path_matches_execution_path(conn, home, fake_binary,
                                              clean_settings):
    """화면에 보이는 경로와 실제 스캔이 쓰는 경로가 갈라지면 안 된다"""
    dependency_service.set_path(conn, "nuclei", str(fake_binary))
    entry = next(
        i for i in dependency_service.status(conn)["items"] if i["key"] == "nuclei"
    )
    assert entry["path"] == settings.nuclei_bin()


def test_missing_override_is_not_reported_available(conn, home, monkeypatch,
                                                    clean_settings):
    """지정만 되어 있고 실제로 없는 경로를 '사용 가능' 으로 보고하지 않음"""
    monkeypatch.setenv("REDAR_NUCLEI", "/nonexistent/nuclei")
    entry = next(
        i for i in dependency_service.status(conn)["items"] if i["key"] == "nuclei"
    )
    assert entry["available"] is False
    assert entry["version"] is None
    assert entry["source"] is None

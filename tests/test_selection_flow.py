"""스캔 흐름 두 모드. nuclei 대신 명령을 기록하는 러너를 주입"""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.adapters.nuclei import runner
from app.domain.template_exclusion import ENUMERATOR_IDS
from app.main import app
from app.repository import settings_repo
from app.repository.db import session
from app.services import scan_service
from app.services.scan_service import ScanService

API = "/api/v1"


def test_build_command_excludes_ids_and_accepts_list():
    cmd = runner.build_command(
        runner.RunOptions(targets=["http://a"], template_list="/tmp/l.txt",
                          template_paths=["/c"], exclude_ids=list(ENUMERATOR_IDS)),
        exe="/usr/bin/nuclei",
    )
    assert cmd[cmd.index("-eid") + 1] == ",".join(ENUMERATOR_IDS)
    t_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-t"]
    assert t_values == ["/tmp/l.txt", "/c"]


def test_build_command_without_exclusions_has_no_eid():
    cmd = runner.build_command(runner.RunOptions(targets=["http://a"]), exe="/usr/bin/nuclei")
    assert "-eid" not in cmd


class _Recorder:
    """호출된 RunOptions 기록. 출력 없음"""

    def __init__(self):
        self.options: list[runner.RunOptions] = []

    def build(self, opts):
        self.options.append(opts)
        return ["fake", str(len(self.options))]

    def run(self, command, *, on_stdout_line, on_stderr_line=None, cancel=None):
        return 0


def _run_scan(db_path, mode):
    rec = _Recorder()
    scan_service.set_service(ScanService(
        db_path, command_builder=rec.build, command_runner=rec.run,
        prober=lambda t: list(t),
    ))
    try:
        with TestClient(app) as client:
            # 환경 조사는 환경 기반 모드에서만 필수. 나머지는 꺼서 실제 요청을 막음
            body = {"targets": ["http://localhost:7860"],
                    "template_selection": {"mode": mode},
                    "collect_environment": mode == "environment_driven"}
            created = client.post(f"{API}/scans", json=body)
            assert created.status_code == 202, created.text
            scan_id = created.json()["scan_id"]
            view = {}
            for _ in range(200):
                view = client.get(f"{API}/scans/{scan_id}").json()
                if view["status"] in ("completed", "failed", "canceled"):
                    break
                time.sleep(0.05)
    finally:
        scan_service.set_service(None)
    return rec, view


@pytest.fixture
def seeded(db_path):
    """사전 점검 통과용 템플릿 1건. 세션 DB 오염 방지를 위해 반드시 제거"""
    with session(db_path) as conn:
        conn.execute("INSERT OR IGNORE INTO templates (template_id, source, file_path, name)"
                     " VALUES ('redar-seed', 'custom', '/tmp/seed.yaml', 'seed')")
        conn.commit()
    yield
    with session(db_path) as conn:
        conn.execute("DELETE FROM templates WHERE template_id = 'redar-seed'")
        conn.commit()


def test_full_scan_runs_once_and_excludes_enumerators(db_path, seeded):
    rec, view = _run_scan(db_path, "full_scan")
    assert view["status"] == "completed"
    assert len(rec.options) == 1
    assert list(rec.options[0].exclude_ids) == list(ENUMERATOR_IDS)
    basis = view["selection_basis"]
    assert basis["mode"] == "full_scan"
    assert basis["universe"] == "all_templates"
    assert basis["excluded_enumerators"] == list(ENUMERATOR_IDS)


def test_wp_full_enumeration_opt_in(db_path, seeded):
    with session(db_path) as conn:
        settings_repo.put_many(conn, {"scan_wp_full_enumeration": True})
    try:
        rec, view = _run_scan(db_path, "full_scan")
        assert list(rec.options[0].exclude_ids) == []
        assert view["selection_basis"]["wp_full_enumeration"] is True
    finally:
        with session(db_path) as conn:
            settings_repo.put_many(conn, {"scan_wp_full_enumeration": False})


def test_explicit_mode_keeps_user_choice(db_path, seeded):
    rec, view = _run_scan(db_path, "explicit")
    assert list(rec.options[0].exclude_ids) == []
    assert view["selection_basis"] is None


def test_filter_mode_excludes_enumerators(db_path, seeded):
    rec, _ = _run_scan(db_path, "filter")
    assert list(rec.options[0].exclude_ids) == list(ENUMERATOR_IDS)


def test_environment_driven_without_prepass_falls_back_to_all(db_path, seeded, monkeypatch):
    """사전 패스 템플릿이 없으면 제외 없이 전체 (애매하면 전체)"""
    # 노출 수집기는 실제 요청을 보냄. Windows 는 닫힌 포트 연결에 2초씩 걸려 대기 초과
    monkeypatch.setattr(
        "app.services.environment_service.collect_target", lambda *a, **k: None
    )
    rec, view = _run_scan(db_path, "environment_driven")
    assert view["status"] == "completed"
    basis = view["selection_basis"]
    assert basis["mode"] == "environment_driven"
    assert basis["excluded"] == []
    assert basis["fallback_reason"] == "no_index"
    assert len(rec.options) == 1
    assert rec.options[0].template_list is None

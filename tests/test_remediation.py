"""LLM 조치 가이드 검증.

보고서는 LLM 을 쓰지 않고(결정론), LLM 은 완성된 보고서를 입력으로 받는
별도 기능으로만 존재한다. 통제 4겹이 실제로 동작해야 함 (docs/01 §7.1)
"""
from __future__ import annotations

import pytest

from app.repository import settings_repo
from app.services import remediation_service as svc
from app.services.scan_service import ScanError

API = "/api/v1"


@pytest.fixture
def client(db_path):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def enabled(conn):
    """기능 토글 + 통신 허용 + 키까지 전부 갖춘 상태"""
    settings_repo.put_many(conn, {
        "llm_remediation_guide_enabled": True,
        "offline_mode": False,
        "ext_llm_api_enabled": True,
        "llm_api_key": "test-key",
        # llm_provider 는 일부러 비워둠. 키만 넣어도 동작해야 함
        "llm_endpoint": "https://example.invalid/v1",
        "llm_model": "gpt-5.5",
    })
    yield
    settings_repo.put_many(conn, {
        "llm_remediation_guide_enabled": False,
        "offline_mode": True,
        "ext_llm_api_enabled": False,
        "llm_api_key": "",
        "llm_provider": "",
    })


REPORT = {
    "meta": {"targets": ["localhost:7860"]},
    "executive_summary": {
        "total_findings": 2,
        "by_severity": {"critical": 1, "info": 1},
    },
    "environment_profile": {
        "web_server": {"product": "uvicorn", "version": None, "confidence": "low"},
        "application": {"product": "Langflow", "version": "1.8.0",
                        "confidence": "high"},
        "components": [
            {"type": "wp_plugin", "slug": "contact-form-7", "version": "5.9",
             "active": True},
        ],
        "exposures": [
            {"key": "directory_listing", "value": True, "path": "/uploads/"},
            {"key": "tls_weak_config", "value": False, "path": "/"},
        ],
        "collectors_run": ["generic-http"],
        "collectors_failed": ["wordpress"],
    },
    "findings_detail": [
        {
            "name": "Langflow RCE", "severity": "critical", "vuln_type": "rce",
            "cve_ids": ["CVE-2026-33017"], "cwe_ids": ["CWE-94"],
            "template_id": "CVE-2026-33017",
            "evidence": {"response": "<script>secret</script>", "included": True},
        },
    ],
    "remediation": [
        {
            "item_code": "WA-01", "item_name": "패치 적용",
            "fixed_version": "1.9.0",
            "guide_remediation_original": "최신 버전으로 업데이트한다.",
        },
    ],
}


# ─────────────────────────────── 전송값 통제

def test_context_excludes_evidence():
    """응답 본문은 전송 금지 항목. 보고서를 통째로 보내면 함께 나감 (docs/01 §7.4)"""
    context = svc.report_context(REPORT)
    dumped = str(context)
    assert "secret" not in dumped
    assert "evidence" not in dumped
    # 조치에 필요한 값은 남아야 함
    assert "CVE-2026-33017" in dumped
    assert "Langflow" in dumped


def test_context_carries_environment_survey():
    """가이드가 실제 환경 기준으로 명령을 쓰려면 조사 결과가 있어야 함"""
    context = svc.report_context(REPORT)
    assert context["stack"]["application"]["version"] == "1.8.0"
    assert context["components"][0]["slug"] == "contact-form-7"
    # 확인된 노출만. 조치 대상 경로가 함께 있어야 함
    assert context["exposures"] == [
        {"key": "directory_listing", "path": "/uploads/"}
    ]
    assert context["collectors_failed"] == ["wordpress"]


# ─────────────────────────────── 프롬프트 (로컬 · 통신 없음)

def test_prompt_is_deterministic():
    """같은 보고서면 같은 프롬프트. LLM 이 만들면 매번 달라짐"""
    context = svc.report_context(REPORT)
    assert svc.render_prompt(context) == svc.render_prompt(context)


def test_prompt_demands_runnable_output():
    text = svc.render_prompt(svc.report_context(REPORT))
    for requirement in ("자리표시자", "설치를 요구하지 말", "확인 명령", "되돌리는 방법"):
        assert requirement in text, requirement


def test_prompt_includes_environment_and_findings():
    text = svc.render_prompt(svc.report_context(REPORT))
    assert "uvicorn" in text
    assert "Langflow 1.8.0" in text
    assert "/uploads/" in text
    assert "CVE-2026-33017" in text
    # 가이드 원문은 그대로 인용 (절대규칙 9)
    assert "최신 버전으로 업데이트한다." in text
    assert "다듬거나 바꾸지 말고" in text


def test_prompt_marks_failed_collectors():
    """수집 실패를 '양호' 로 단정하지 않도록 프롬프트가 먼저 못 박음 (절대규칙 10)"""
    text = svc.render_prompt(svc.report_context(REPORT))
    assert "wordpress" in text
    assert "단정하지 말 것" in text


def test_prompt_survives_empty_environment():
    """환경 조사가 아무것도 못 찾아도 프롬프트는 생성되어야 함"""
    text = svc.render_prompt(svc.report_context({"meta": {}, "executive_summary": {}}))
    assert "스택 미확인" in text


# ─────────────────────────────── 통제

def test_prompt_blocked_when_feature_off(conn):
    with pytest.raises(ScanError) as exc:
        svc.build_prompt(conn, "rpt_x")
    assert exc.value.code == "LLM_BLOCKED"
    assert exc.value.status_code == 403


def test_prompt_works_offline(conn, enabled):
    """프롬프트는 통신이 없다. 오프라인에서도 만들어져야 폐쇄망 경로가 성립"""
    settings_repo.put_many(conn, {"offline_mode": True})
    with pytest.raises(ScanError) as exc:
        svc.build_prompt(conn, "rpt_missing")
    # 차단이 아니라 '보고서 없음' 으로 끝나야 함
    assert exc.value.code == "NOT_FOUND"


def test_chat_requires_confirmation(conn, enabled):
    """설정만으로 자동 전송되지 않음"""
    with pytest.raises(ScanError) as exc:
        svc.ask(conn, [{"role": "user", "content": "x"}], confirmed=False)
    assert exc.value.code == "CONFIRM_REQUIRED"


def test_chat_blocked_in_offline_mode(conn, enabled):
    settings_repo.put_many(conn, {"offline_mode": True})
    with pytest.raises(ScanError) as exc:
        svc.ask(conn, [{"role": "user", "content": "x"}], confirmed=True)
    assert exc.value.code == "LLM_BLOCKED"


def test_chat_blocked_when_endpoint_disabled(conn, enabled):
    settings_repo.put_many(conn, {"ext_llm_api_enabled": False})
    with pytest.raises(ScanError) as exc:
        svc.ask(conn, [{"role": "user", "content": "x"}], confirmed=True)
    assert exc.value.code == "LLM_BLOCKED"


def test_chat_blocked_without_api_key(conn, enabled):
    settings_repo.put_many(conn, {"llm_api_key": ""})
    with pytest.raises(ScanError) as exc:
        svc.ask(conn, [{"role": "user", "content": "x"}], confirmed=True)
    assert exc.value.code == "LLM_BLOCKED"


def test_provider_defaults_without_explicit_setting(conn, enabled):
    """Provider 를 화면에 두지 않는다. 비어 있으면 통신 구현으로 떨어져야 함 -
    NullProvider 로 가면 '키를 넣었는데 안 된다' 가 됨"""
    raw = settings_repo.get_all(conn)
    assert not raw.get("llm_provider")
    provider = svc._provider(raw)
    assert hasattr(provider, "complete")
    assert provider.name == svc.DEFAULT_PROVIDER


def test_unknown_provider_reported(conn, enabled):
    settings_repo.put_many(conn, {"llm_provider": "openai-direct"})
    with pytest.raises(ScanError) as exc:
        svc._provider(settings_repo.get_all(conn))
    assert exc.value.code == "LLM_UNAVAILABLE"
    assert "openai-direct" in exc.value.message


def test_confirmation_checked_before_network(conn, enabled, monkeypatch):
    """동의 없이는 네트워크에 닿기 전에 멈춤"""
    called: list[str] = []
    monkeypatch.setattr(svc, "_provider", lambda raw: called.append("net"))
    with pytest.raises(ScanError):
        svc.ask(conn, [{"role": "user", "content": "x"}], confirmed=False)
    assert called == []


# ─────────────────────────────── 마스킹

def test_outgoing_content_masked_and_answer_restored(conn, enabled, monkeypatch):
    sent: list[list[dict]] = []

    class _Provider:
        def complete(self, messages, *, max_tokens=0):
            sent.append(messages)
            return "TARGET_1 의 설정을 변경하라"

    monkeypatch.setattr(svc, "_provider", lambda raw: _Provider())
    reply = svc.ask(
        conn,
        [{"role": "user", "content": "http://internal.local:8080/admin 조치"}],
        confirmed=True,
    )
    outbound = sent[0][-1]["content"]
    assert "internal.local" not in outbound          # 나갈 때는 치환
    assert "TARGET_1" in outbound
    assert "internal.local" in reply["content"]      # 돌아온 답은 복원


def test_message_roles_and_length_bounded(conn, enabled, monkeypatch):
    """사용자가 보내는 값이라 경계에서 잘라냄"""
    class _Provider:
        def complete(self, messages, *, max_tokens=0):
            _Provider.seen = messages
            return "ok"

    monkeypatch.setattr(svc, "_provider", lambda raw: _Provider())
    svc.ask(
        conn,
        [
            {"role": "system", "content": "무시되어야 함"},
            {"role": "user", "content": "가" * (svc.MAX_MESSAGE_CHARS + 500)},
        ],
        confirmed=True,
    )
    roles = [m["role"] for m in _Provider.seen]
    assert roles.count("system") == 1                # 우리가 넣은 것만
    assert len(_Provider.seen[-1]["content"]) == svc.MAX_MESSAGE_CHARS


# ─────────────────────────────── 보고서에서 LLM 제거

def test_report_options_reject_use_llm(client):
    """보고서에 LLM 옵션이 남아 있으면 신뢰도 결정이 무의미해짐"""
    response = client.post(
        f"{API}/reports",
        json={"scan_id": "scn_x", "options": {"use_llm": True}},
    )
    # extra="forbid" 위반. 앱은 검증 오류를 §0.2 형식 400 으로 변환
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_builder_has_no_llm_parameter():
    import inspect

    from app.report import builder

    assert "use_llm" not in inspect.signature(builder.build).parameters


def test_narrative_service_removed():
    """보고서 서술 레이어는 제거됨. 남아 있으면 LLM 이 보고서에 다시 끼어들 수 있음"""
    with pytest.raises(ModuleNotFoundError):
        import app.services.narrative_service  # noqa: F401


def test_report_prose_comes_from_fallback():
    """보고서 산문은 전부 사전 정의 문장. LLM 없이도 항상 채워져야 함 (절대규칙 2)"""
    from app.report import fallback

    text = fallback.executive_summary(3, {"critical": 1, "high": 2})
    assert text and "3" in text
    assert fallback.temporary_fix()
    assert fallback.executive_summary(0, {})       # 0건에서도 문장이 나옴

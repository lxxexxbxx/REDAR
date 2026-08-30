"""GUI 정적 서빙 + guide/status 검증."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.domain import models
from fastapi.testclient import TestClient

from app.main import app

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


def _notice_tail() -> str:
    """고지 문구의 고정부. 표현이 바뀌어도 존재 여부는 계속 검증"""
    return models.COVERAGE_NOTICE_TEMPLATE.split("{scope}")[-1].strip()

@pytest.fixture(scope="module")
def client(request):
    request.getfixturevalue("db_path")
    with TestClient(app) as test_client:
        yield test_client


def test_guide_status_reports_bundled_mapping(client):
    """본문 미탑재 + 매핑 존재 = 정상 상태 (절대규칙 3)"""
    body = client.get("/api/v1/guide/status").json()
    assert body["imported"] is False
    assert body["item_count"] == 0
    assert body["mapping_count"] == 454
    assert body["items_covered"] == 36


@pytest.mark.parametrize(
    "path,content_type",
    [
        ("/", "text/html"),
        ("/css/app.css", "text/css"),
        ("/js/app.js", "javascript"),
        ("/js/api.js", "javascript"),
        ("/js/ui.js", "javascript"),
    ],
)
def test_static_assets_served(client, path, content_type):
    response = client.get(path)
    assert response.status_code == 200
    assert content_type in response.headers["content-type"]


def test_fonts_served(client):
    """woff2 MIME 은 OS 레지스트리 의존. 크기만 확인"""
    for name in ("NanumGothic.woff2", "NanumGothicBold.woff2", "D2Coding.woff2"):
        response = client.get(f"/fonts/{name}")
        assert response.status_code == 200
        assert len(response.content) > 100_000


def test_api_routes_win_over_static_mount(client):
    """루트 마운트가 API 경로를 가리지 않음"""
    assert client.get("/api/v1/health").json()["status"] == "ok"


# 리소스를 실제로 불러오는 위치만 검사. 입력창 placeholder 의 localhost 는 대상 아님
_RESOURCE_REF = re.compile(
    r"""(?:src|href)\s*=\s*["'](https?://[^"']+)|url\(\s*["']?(https?://[^"')]+)"""
)


def test_frontend_loads_no_external_resources():
    """CDN·외부 폰트 참조 금지. 오프라인 동작 보장 (절대규칙 5)"""
    offenders = []
    for file in FRONTEND.rglob("*"):
        if file.suffix not in (".html", ".css", ".js"):
            continue
        for groups in _RESOURCE_REF.findall(file.read_text(encoding="utf-8")):
            url = next(g for g in groups if g)
            offenders.append(f"{file.name}: {url}")
    assert not offenders, offenders


def test_coverage_notice_has_single_source(client):
    """고지 문장 사본이 프론트에 생기면 보고서와 갈라짐 (절대규칙 10)."""
    served = client.get("/api/v1/guide/status").json()["coverage_notice"]
    assert _notice_tail() in served

    frontend_text = "".join(
        f.read_text(encoding="utf-8")
        for f in FRONTEND.rglob("*")
        if f.suffix in (".js", ".html")
    )
    assert "탐지되지 않음이 양호를" not in frontend_text


def test_gui_labels_match_backend_enums():
    """GUI 표시 문자열과 백엔드 Enum 라벨 불일치 시 화면·보고서 괴리 발생"""
    from app.domain.enums import (
        SEVERITY_LABELS, VULN_TYPE_LABELS, Severity, VulnType,
    )

    text = (FRONTEND / "js" / "ui.js").read_text(encoding="utf-8")

    def labels_of(block_name: str) -> dict[str, str]:
        block = re.search(rf"{block_name} = \{{(.*?)\n\}};", text, re.S).group(1)
        return dict(re.findall(r'(\w+):\s*"([^"]+)"', block))

    severity = labels_of("SEVERITY_LABEL")
    vuln = labels_of("VULN_TYPE_LABEL")

    assert severity == {s.value: SEVERITY_LABELS[s] for s in Severity}
    assert vuln == {v.value: VULN_TYPE_LABELS[v] for v in VulnType}

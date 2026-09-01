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
        ("/js/tasks.js", "javascript"),
    ],
)
def test_static_assets_served(client, path, content_type):
    response = client.get(path)
    assert response.status_code == 200
    assert content_type in response.headers["content-type"]


def test_every_module_import_resolves():
    """import 경로가 틀리면 화면이 통째로 안 뜬다. 브라우저 없이 정적 확인"""
    missing = []
    for file in (FRONTEND / "js").glob("*.js"):
        for spec in re.findall(r'from\s+"\./([A-Za-z0-9_.-]+)"', file.read_text("utf-8")):
            if not (FRONTEND / "js" / spec).is_file():
                missing.append(f"{file.name} -> {spec}")
    assert not missing, missing


def test_report_options_match_backend_schema():
    """GUI 가 보내는 옵션이 스키마에 없으면 extra='forbid' 로 400.
    화면에서 눌러봐야 알게 되므로 정적으로 잡음"""
    from app.api.reports import ReportOptions

    allowed = set(ReportOptions.model_fields)
    source = (FRONTEND / "js" / "reports.js").read_text(encoding="utf-8")
    body = source.split("api.createReport(")[1].split("})")[0]
    sent = set(re.findall(r"^\s*([a-z_]+):", body, re.M))
    assert sent <= allowed, f"스키마에 없는 옵션: {sent - allowed}"
    assert sent, "옵션을 하나도 보내지 않으면 검사가 무의미"


def test_scan_done_updates_dock_before_dom():
    """다른 화면으로 옮기면 스캔 화면 요소가 없다. 그 DOM 접근이 먼저 오면
    예외가 나고 도크가 영원히 '진행 중' 으로 남는다 (실제 발생)"""
    source = (FRONTEND / "js" / "app.js").read_text(encoding="utf-8")
    body = source.split("done(event) {")[1].split("\n    },")[0]
    dock = min(body.index("tasks.done"), body.index("tasks.fail"))
    dom = body.index("getElementById")
    assert dock < dom, "도크 갱신이 DOM 접근보다 먼저여야 함"


def test_scan_handlers_guard_missing_elements():
    """스캔 화면을 떠난 뒤 도착하는 이벤트가 예외를 내면 안 됨"""
    source = (FRONTEND / "js" / "app.js").read_text(encoding="utf-8")
    body = source.split("state.unsubscribe = subscribeScan(")[1].split("\n  });")[0]
    bare = re.findall(r'getElementById\("([\w-]+)"\)\.\w', body)
    assert not bare, f"보호되지 않은 DOM 접근: {bare}"


def test_task_dock_mounted_outside_view():
    """작업 도크가 #view 안에 있으면 화면 전환마다 지워진다"""
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert 'id="taskdock"' in html
    # 도크가 본문 컨테이너 뒤에 와야 재렌더에 살아남음
    assert html.index('id="view"') < html.index('id="taskdock"')
    assert "taskdock" not in html.split('id="view"')[1].split("</main>")[0]


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

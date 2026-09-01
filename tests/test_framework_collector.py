"""애플리케이션 식별 검증.

헤더만 보던 방식으로는 uvicorn 뒤의 Langflow 처럼 제품·버전이 통째로 미확인으로
남았다. 환경 기반 템플릿 선별의 입력이라 여기가 비면 스캔 품질이 떨어짐

요청 수도 함께 검증한다. 탐지가 늘어도 조사 시간이 비례해 늘면 쓸 수 없음
"""
from __future__ import annotations

import json

from app.collectors import base
from app.collectors.framework import COLLECTOR
from app.domain.enums import Confidence


def _ctx(pages: dict[str, tuple[int, dict, str]], port: int | None = None,
         collected: dict | None = None) -> tuple[base.TargetContext, list[str]]:
    """가짜 대상. 요청 경로를 순서대로 기록해 호출 횟수를 검증"""
    asked: list[str] = []

    def http(url, *, method="GET", timeout=5):
        path = url.split("://", 1)[1].split("/", 1)
        path = "/" + (path[1] if len(path) > 1 else "")
        asked.append(path)
        if path not in pages:
            return base.Response(status=404, headers={}, text="", url=url)
        status, headers, body = pages[path]
        return base.Response(
            status=status,
            headers={k.lower(): v for k, v in headers.items()},
            text=body, url=url,
        )

    ctx = base.TargetContext(
        scheme="http", host="localhost", port=port, http=http,
        collected=collected or {},
    )
    return ctx, asked


# ─────────────────────────────── 추가 요청 없이 얻는 것

def test_meta_generator_gives_product_and_version():
    ctx, asked = _ctx({
        "/": (200, {}, '<meta name="generator" content="Drupal 10.2.1 (https://d.org)">'),
    })
    result = COLLECTOR.collect(ctx)
    assert result.application.product == "Drupal"
    assert result.application.version == "10.2.1"
    assert result.application.confidence == Confidence.HIGH
    # 버전까지 확정했으면 더 묻지 않음
    assert asked == ["/"]


def test_header_product_without_extra_request():
    ctx, asked = _ctx({"/": (200, {"X-Jenkins": "2.440.1"}, "")})
    result = COLLECTOR.collect(ctx)
    assert result.application.product == "Jenkins"
    assert result.application.version == "2.440.1"
    assert asked == ["/"]


# ─────────────────────────────── 표적 확인

def test_openapi_identifies_application():
    """FastAPI 계열은 헤더로 알 수 없다. 표준 경로 1회로 제품·버전 확보"""
    ctx, asked = _ctx({
        "/": (200, {"Server": "uvicorn"}, "<html><body>app</body></html>"),
        "/openapi.json": (200, {}, json.dumps({
            "info": {"title": "Langflow", "version": "1.8.0"},
        })),
    })
    result = COLLECTOR.collect(ctx)
    assert result.application.product == "Langflow"
    assert result.application.version == "1.8.0"
    assert asked.count("/") == 1                 # 루트는 한 번만


def test_default_port_reorders_probes():
    """기본 포트는 어느 경로를 먼저 볼지 고르는 힌트. 단독 근거로 쓰지 않음"""
    ctx, asked = _ctx(
        {
            "/": (200, {"Server": "uvicorn"}, ""),
            "/api/v1/version": (200, {}, json.dumps({"version": "1.8.0"})),
        },
        port=7860,
    )
    result = COLLECTOR.collect(ctx)
    assert result.application.version == "1.8.0"
    assert asked[1] == "/api/v1/version"         # 포트에 맞는 경로를 먼저


def test_probe_count_bounded():
    """아무것도 안 나오는 대상에서 확인 요청이 무한정 늘지 않아야 함"""
    ctx, asked = _ctx({"/": (200, {"Server": "nginx/1.24.0"}, "")})
    COLLECTOR.collect(ctx)
    assert len(asked) <= 1 + 2                    # 루트 + 상한 2회


def test_port_hint_alone_does_not_confirm():
    """포트만 맞고 응답이 없으면 제품을 단정하지 않음"""
    ctx, _ = _ctx({"/": (200, {}, "")}, port=7860)
    result = COLLECTOR.collect(ctx)
    assert result.application is None


# ─────────────────────────────── 언어 런타임

def test_runtime_inferred_from_server_product():
    """uvicorn 이면 Python 이다. '미수집' 보다 낫지만 추정이므로 low"""
    ctx, _ = _ctx({"/": (200, {"Server": "uvicorn"}, "")})
    result = COLLECTOR.collect(ctx)
    assert result.language.product == "Python"
    assert result.language.confidence == Confidence.LOW
    assert "추정" in result.language.evidence


def test_runtime_from_cookie():
    ctx, _ = _ctx({"/": (200, {"Set-Cookie": "PHPSESSID=abc; Path=/"}, "")})
    result = COLLECTOR.collect(ctx)
    assert result.language.product == "PHP"


def test_runtime_not_overwritten_when_already_found():
    """generic-http 가 X-Powered-By 로 찾은 값을 추정값으로 덮지 않음"""
    from app.collectors.base import CollectResult, StackFinding

    prior = CollectResult(language=StackFinding(product="PHP", version="8.2.0"))
    ctx, _ = _ctx({"/": (200, {"Server": "uvicorn"}, "")},
                  collected={"generic-http": prior})
    result = COLLECTOR.collect(ctx)
    assert result.language is None


# ─────────────────────────────── 다른 수집기와의 경계

def test_application_not_reprobed_when_already_identified():
    """WordPress 로 확정된 대상에 표적 확인을 돌리면 요청만 낭비.
    단 언어 런타임은 계속 채운다 - 애플리케이션과 별개 정보"""
    from app.collectors.base import CollectResult, StackFinding

    prior = CollectResult(
        application=StackFinding(product="WordPress", version="6.4.2")
    )
    ctx, asked = _ctx(
        {"/": (200, {"Set-Cookie": "PHPSESSID=a"}, "")},
        collected={"wordpress": prior},
    )
    assert COLLECTOR.applicable(ctx) is True
    result = COLLECTOR.collect(ctx)
    assert result.application is None            # 덮어쓰지 않음
    assert result.language.product == "PHP"      # 런타임은 채움
    assert asked == ["/"]                        # 표적 확인 없음


def test_registered_in_registry():
    assert any(c.key == "framework" for c in base.registry())


# ─────────────────────────────── 응답 캐시

def test_same_path_requested_once():
    """수집기 여러 개가 각자 '/' 를 읽으면 대상에 같은 요청이 반복됨"""
    ctx, asked = _ctx({"/": (200, {}, "")})
    ctx.get("/")
    ctx.get("/")
    ctx.get("/", method="HEAD")
    assert asked.count("/") == 2                  # GET 1회 + HEAD 1회

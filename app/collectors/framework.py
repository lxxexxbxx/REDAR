"""애플리케이션·프레임워크 식별.

WordPress 는 전용 수집기가 담당한다. 이 수집기는 그 밖의 애플리케이션을 맡는다.
헤더만 보던 기존 방식으로는 uvicorn 뒤의 Langflow 처럼 **제품과 버전이 통째로
미확인**으로 남았다. 환경 기반 템플릿 선별의 입력이라 여기가 비면 스캔 품질이 떨어짐

탐지 순서 - 요청 수를 최소로 유지
  [1] 이미 받아온 '/' 응답에서 추출     추가 요청 0회
      meta generator · 헤더 지문 · 쿠키 지문 · Server 제품 -> 언어 런타임 추론
  [2] [1]에서 버전을 못 찾은 경우에만 표적 확인   최대 _MAX_PROBES 회
      표식이 맞거나 기본 포트가 맞는 후보만 확인

기본 포트를 '단독 근거' 로 쓰지 않는다. 도커에서 포트는 자유롭게 바뀌므로
포트는 어느 경로를 먼저 확인할지 고르는 힌트로만 쓰고, 판단은 응답이 한다
"""
from __future__ import annotations

import json
import re

from app.collectors.base import (
    ORDER_APPLICATION,
    CollectResult,
    Response,
    StackFinding,
    TargetContext,
)
from app.domain.enums import Confidence

# 표적 확인 상한. 늘리면 조사 시간이 그만큼 늘어남
_MAX_PROBES = 2

# <meta name="generator" content="Drupal 10 (https://www.drupal.org)">
_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", re.I
)
# 'Drupal 10.2.1' 처럼 제품명 뒤 버전. 없으면 제품만
_PRODUCT_VERSION_RE = re.compile(r"^\s*([A-Za-z][\w.+ -]*?)[\s/v]*([\d][\d.]*)?\s*(?:\(|$)")

# Server 제품 -> 언어 런타임. 헤더가 언어를 직접 알려주지 않는 조합이 많음
# 확신도는 low. 서버 소프트웨어로 런타임을 유추한 것이며 버전은 알 수 없음
_RUNTIME_BY_SERVER = {
    "uvicorn": "Python", "gunicorn": "Python", "hypercorn": "Python",
    "waitress": "Python", "werkzeug": "Python", "daphne": "Python",
    "express": "Node.js", "next.js": "Node.js",
    "puma": "Ruby", "unicorn": "Ruby", "passenger": "Ruby",
    "tomcat": "Java", "jetty": "Java", "coyote": "Java",
    "kestrel": "ASP.NET",
}

# 쿠키 이름 -> 언어 런타임
_RUNTIME_BY_COOKIE = {
    "phpsessid": "PHP", "laravel_session": "PHP",
    "jsessionid": "Java", "asp.net_sessionid": "ASP.NET",
    "connect.sid": "Node.js", "csrftoken": "Python", "sessionid": "Python",
}

# 헤더 하나로 제품이 확정되는 경우. 추가 요청이 필요 없음
_HEADER_PRODUCT = (
    ("x-jenkins", "Jenkins"),
    ("x-drupal-dynamic-cache", "Drupal"),
    ("x-generator", None),          # 값이 곧 제품 표기
)


class _Probe:
    """표적 확인 1건. path 를 읽어 (제품, 버전) 을 뽑음"""

    def __init__(self, path: str, ports: tuple[int, ...], reader) -> None:
        self.path = path
        self.ports = ports
        self.reader = reader


def _read_openapi(body: str) -> tuple[str | None, str | None]:
    """OpenAPI 문서. FastAPI·Langflow 등 API 서버 대부분이 노출"""
    info = (_json(body) or {}).get("info") or {}
    title = info.get("title")
    version = info.get("version")
    return (str(title) if title else None,
            str(version) if version else None)


def _read_version_field(body: str) -> tuple[str | None, str | None]:
    """{"version": "1.8.0"} 형태. 제품명은 알려주지 않음"""
    data = _json(body) or {}
    version = data.get("version") or (data.get("data") or {}).get("version")
    return None, str(version) if version else None


# 확인 경로. 순서는 포트 힌트로 재정렬됨
_PROBES = (
    # Langflow·Gradio 기본 포트. /api/v1/version 은 제품 전용 경로
    _Probe("/api/v1/version", (7860,), _read_version_field),
    # FastAPI·Starlette 계열 표준 경로. 제목과 버전을 함께 얻음
    _Probe("/openapi.json", (), _read_openapi),
    # Grafana
    _Probe("/api/health", (3000,), _read_version_field),
)


class FrameworkCollector:
    key = "framework"
    label = "애플리케이션 식별"
    version = "0.1.0"
    detects = ("application", "language_runtime")
    # wordpress 다음. applicable() 이 'WordPress 로 확정됐는지' 를 보므로
    # 같은 순위로 두면 알파벳순으로 앞서 실행되어 그 판단이 무의미해짐
    order = ORDER_APPLICATION + 1

    def applicable(self, ctx: TargetContext) -> bool:
        # 항상 적용. 애플리케이션이 이미 확정된 대상에서도 언어 런타임은 채울 수 있음
        return True

    def collect(self, ctx: TargetContext) -> CollectResult:
        result = CollectResult()
        root = ctx.get("/")

        # 언어 런타임은 애플리케이션 확정 여부와 무관하게 시도.
        # WordPress 대상이라도 X-Powered-By 가 없으면 여기가 유일한 단서
        result.language = _runtime(root, ctx)

        if _identified(ctx):
            # 앞선 수집기가 제품·버전을 확정. 표적 확인을 돌리면 요청만 낭비
            return result

        # [1] 추가 요청 없이 얻을 수 있는 것부터
        result.application = _from_root(root)
        if result.application and result.application.version:
            return result                  # 버전까지 확정. 더 물어볼 필요 없음

        # [2] 표적 확인. 포트 힌트가 맞는 후보를 먼저 봄
        found = _probe(ctx)
        if found is not None:
            result.application = _merge(result.application, found)
        return result


def _identified(ctx: TargetContext) -> bool:
    """앞선 수집기가 애플리케이션 제품을 확정했는지"""
    return any(
        result.application and result.application.product
        for result in ctx.collected.values()
    )


def _from_root(root: Response) -> StackFinding | None:
    if not (root.ok or root.status):
        return None

    match = _GENERATOR_RE.search(root.text or "")
    if match:
        product, version = _split(match.group(1))
        if product:
            return StackFinding(
                product=product, version=version,
                confidence=Confidence.HIGH if version else Confidence.MEDIUM,
                evidence=f"meta generator: {match.group(1)[:120]}",
            )

    for name, fixed in _HEADER_PRODUCT:
        raw = root.header(name)
        if not raw:
            continue
        product, version = (fixed, raw.strip()) if fixed else _split(raw)
        if product:
            return StackFinding(
                product=product, version=version,
                confidence=Confidence.HIGH if version else Confidence.MEDIUM,
                evidence=f"{name}: {raw[:120]}",
            )
    return None


def _runtime(root: Response, ctx: TargetContext) -> StackFinding | None:
    """언어 런타임. generic-http 가 X-Powered-By 로 못 찾은 경우를 메움"""
    existing = (ctx.collected.get("generic-http") or CollectResult()).language
    if existing and existing.product:
        return None                        # 앞선 수집기가 이미 찾음

    server = (root.header("server") or "").lower()
    for needle, runtime in _RUNTIME_BY_SERVER.items():
        if needle in server:
            return StackFinding(
                product=runtime, version=None,
                # 서버 소프트웨어로 런타임을 유추. 버전은 알 수 없음
                confidence=Confidence.LOW,
                evidence=f"Server: {root.header('server')[:80]} -> {runtime} 추정",
            )

    cookies = (root.header("set-cookie") or "").lower()
    for needle, runtime in _RUNTIME_BY_COOKIE.items():
        if needle in cookies:
            return StackFinding(
                product=runtime, version=None, confidence=Confidence.LOW,
                evidence=f"쿠키 {needle} -> {runtime} 추정",
            )
    return None


def _probe(ctx: TargetContext) -> StackFinding | None:
    ordered = sorted(
        _PROBES, key=lambda p: 0 if ctx.port and ctx.port in p.ports else 1
    )
    for probe in ordered[:_MAX_PROBES]:
        response = ctx.get(probe.path)
        if not response.ok:
            continue
        product, version = probe.reader(response.text or "")
        if not (product or version):
            continue
        return StackFinding(
            product=product, version=version,
            confidence=Confidence.HIGH if version else Confidence.MEDIUM,
            evidence=f"{probe.path}: "
                     + " ".join(filter(None, [product, version]))[:120],
        )
    return None


def _merge(base: StackFinding | None, found: StackFinding) -> StackFinding:
    """제품명은 앞선 근거를, 버전은 확인된 값을 씀"""
    if base is None or not base.product:
        return found
    return StackFinding(
        product=base.product,
        version=found.version or base.version,
        confidence=found.confidence if found.version else base.confidence,
        evidence="; ".join(filter(None, [base.evidence, found.evidence])),
    )


def _split(raw: str) -> tuple[str | None, str | None]:
    match = _PRODUCT_VERSION_RE.match(raw or "")
    if not match:
        return None, None
    product = (match.group(1) or "").strip() or None
    return product, match.group(2)


def _json(body: str) -> dict | None:
    try:
        data = json.loads(body[:64 * 1024])
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


COLLECTOR = FrameworkCollector()
